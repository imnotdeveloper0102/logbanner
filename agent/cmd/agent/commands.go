// Manual ban/unban commands from the gateway (stage 6).
//
// The gateway owns the bans row: it writes the row, publishes the
// event for the live feed, and sends a command here on
// logbanner:commands. This listener only applies the command to
// the firewall (or logs it in dry-run); it never writes a bans row,
// so a manual ban cannot be recorded twice. A command for a
// whitelisted IP — the agent-config ranges or a manual_lists entry
// — is refused and logged, the same as a detection ban would be.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"time"

	"github.com/redis/go-redis/v9"

	"logbanner/internal/store"
)

// manualCommand is one message on logbanner:commands.
// DurationSeconds nil means a permanent ban. BanID is the bans
// row the gateway wrote for this command; the agent uses it as the
// audit target when it applies the command, so the admin's audit
// row (target: the ban id) and the agent's row (same target, actor
// "agent") describe the two halves of one manual ban. Older
// commands carry no BanID; the agent then targets the IP instead.
type manualCommand struct {
	Type            string `json:"type"`
	IP              string `json:"ip"`
	BanID           string `json:"ban_id"`
	DurationSeconds *int   `json:"duration_seconds"`
	Reason          string `json:"reason"`
	DryRun          bool   `json:"dry_run"`
}

// handleManualCommand applies one manual ban/unban command to the
// firewall. In dry-run — either the command's own dry_run flag or
// the agent's mode — nothing is applied, only logged, and nothing
// is audited: the gateway already wrote the ban.create row for the
// ban itself, and a dry-run apply changed nothing. A live apply is
// audited (actor "agent", source "manual-command"), so the firewall
// change is traceable even though the gateway owns the bans row.
// Manual commands bypass the circuit breaker and the max-active-
// bans cap: they are an admin's explicit decision, not automatic.
func (b *banner) handleManualCommand(ctx context.Context, cmd manualCommand) {
	ip := net.ParseIP(cmd.IP)
	if ip == nil {
		b.log.Warn("ignoring manual command with invalid IP", "type", cmd.Type, "ip", cmd.IP)
		return
	}
	if b.wl.Contains(ip) {
		b.log.Warn("refusing manual command for whitelisted IP", "type", cmd.Type, "ip", ip.String(), "reason", cmd.Reason)
		return
	}
	if b.store != nil {
		whitelisted, err := b.store.IsManualWhitelisted(ctx, ip)
		if err != nil {
			// The whitelist is unknown, so the safe move is to
			// refuse the ban rather than apply it blind.
			b.log.Error("manual whitelist check failed, refusing command", "type", cmd.Type, "ip", ip.String(), "error", err)
			return
		}
		if whitelisted {
			b.skipped.Add(1)
			b.log.Warn("refusing manual command for manually whitelisted IP", "type", cmd.Type, "ip", ip.String(), "reason", cmd.Reason)
			return
		}
	}
	switch cmd.Type {
	case "ban":
		if cmd.DryRun || b.dryRun {
			b.log.Info("manual ban (dry-run): would ban", "ip", ip.String(), "reason", cmd.Reason, "duration_seconds", cmd.DurationSeconds)
			return
		}
		if err := b.driver.Ban(ctx, ip, cmd.DurationSeconds); err != nil {
			b.log.Error("failed to apply manual ban", "ip", ip.String(), "error", err)
			return
		}
		b.bans.Add(1)
		b.log.Info("manual ban applied", "ip", ip.String(), "reason", cmd.Reason, "duration_seconds", cmd.DurationSeconds)
		b.auditManualCommand(ctx, "ban.create", cmd, map[string]any{
			"ip": ip.String(), "reason": cmd.Reason,
			"duration_seconds": cmd.DurationSeconds, "source": "manual-command",
		})
	case "unban":
		if cmd.DryRun || b.dryRun {
			b.log.Info("manual unban (dry-run): would unban", "ip", ip.String())
			return
		}
		if err := b.driver.Unban(ctx, ip); err != nil {
			b.log.Error("failed to apply manual unban", "ip", ip.String(), "error", err)
			return
		}
		b.log.Info("manual unban applied", "ip", ip.String())
		b.auditManualCommand(ctx, "ban.revoke", cmd, map[string]any{
			"ip": ip.String(), "reason": cmd.Reason, "source": "manual-command",
		})
	default:
		b.log.Warn("ignoring unknown manual command type", "type", cmd.Type, "ip", ip.String())
	}
}

// auditManualCommand writes the audit row for a manual command the
// agent actually applied. Without a store there is nowhere to
// write it; a failed write is logged, never fatal, because the
// firewall change already happened.
func (b *banner) auditManualCommand(ctx context.Context, action string, cmd manualCommand, details map[string]any) {
	if b.store == nil {
		return
	}
	target := cmd.BanID
	if target == "" {
		target = cmd.IP
	}
	if err := b.store.SaveAuditLog(ctx, action, "ban", target, details); err != nil {
		b.log.Error("failed to write manual command audit log", "action", action, "ip", cmd.IP, "error", err)
	}
}

// runCommandListener subscribes to logbanner:commands until ctx is
// done, applying each command as it arrives. A dropped connection
// is retried with a pause instead of killing the agent, because
// detection must keep working when Redis is briefly down; a
// malformed message is logged and skipped, never fatal.
func runCommandListener(ctx context.Context, redisAddr string, b *banner, log *slog.Logger) {
	if redisAddr == "" {
		log.Info("no redis_addr configured, manual ban commands will not be received")
		return
	}
	for {
		client := redis.NewClient(&redis.Options{Addr: redisAddr, DialTimeout: 2 * time.Second})
		sub := client.Subscribe(ctx, store.CommandsChannel)
		_, err := sub.Receive(ctx)
		if err != nil {
			_ = sub.Close()
			_ = client.Close()
			if ctx.Err() != nil {
				return
			}
			log.Warn("manual command subscription failed, retrying", "error", err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}
		log.Info("listening for manual ban commands", "channel", store.CommandsChannel)
		// ReceiveMessage blocks until a message arrives, the
		// subscription drops, or ctx is done.
		for {
			msg, err := sub.ReceiveMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					_ = sub.Close()
					_ = client.Close()
					return
				}
				log.Warn("manual command subscription dropped, reconnecting", "error", err)
				break
			}
			var cmd manualCommand
			if err := json.Unmarshal([]byte(msg.Payload), &cmd); err != nil {
				log.Warn("ignoring malformed manual command", "payload", msg.Payload, "error", err)
				continue
			}
			b.handleManualCommand(ctx, cmd)
		}
		_ = sub.Close()
		_ = client.Close()
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}
