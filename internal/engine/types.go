package engine

import "github.com/pinchtab/idpishield/internal/types"

// Type aliases — engine uses types from internal/types.
type Mode = types.Mode

const (
	ModeFast     = types.ModeFast
	ModeBalanced = types.ModeBalanced
	ModeDeep     = types.ModeDeep
)

type RiskResult = types.RiskResult

var (
	ParseMode       = types.ParseMode
	ParseModeStrict = types.ParseModeStrict
	ScoreToLevel    = types.ScoreToLevel
	ShouldBlock     = types.ShouldBlock
	SafeResult      = types.SafeResult
)
