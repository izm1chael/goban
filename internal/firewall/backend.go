// Package firewall constructs GoBan's privileged local firewall backends.
// Keeping this in one place ensures direct mode and goban-enforcer use the
// same backend configuration semantics.
package firewall

import (
	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
)

func NewLocal(cfg *config.Config, log zerolog.Logger) banner.Banner {
	if cfg.Banner.Backend == "nftables" {
		log.Info().Str("backend", "nftables").Str("table", cfg.Banner.Table).Msg("local firewall backend")
		nft := banner.NewNFTables(cfg.Banner.Table, cfg.Banner.SetV4, cfg.Banner.SetV6, cfg.Banner.Chain, cfg.IPv6)
		nft.SetForwardChain(cfg.Banner.ForwardChain)
		return nft
	}
	log.Info().Str("backend", "iptables").Msg("local firewall backend")
	ipt := banner.NewIPTables(cfg.IPSetNameV4, cfg.IPSetNameV6, cfg.IPv6)
	ipt.SetChains(cfg.Banner.IPTablesChains)
	return ipt
}
