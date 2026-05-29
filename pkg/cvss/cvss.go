package cvss

import (
	"fmt"
	"math"
	"strings"
)

type Vector struct {
	Raw       string
	Version   string
	AV AttackVector
	AC AttackComplexity
	PR PrivilegesRequired
	UI  UserInteraction
	S  Scope
	C  CIA
	I  CIA
	A  CIA
}

type AttackVector string
const (
	AVNetwork      AttackVector = "N"
	AVAdjacent     AttackVector = "A"
	AVLocal        AttackVector = "L"
	AVPhysical     AttackVector = "P"
)

type AttackComplexity string
const (
	ACLow     AttackComplexity = "L"
	ACHigh    AttackComplexity = "H"
)

type PrivilegesRequired string
const (
	PRNone PrivilegesRequired = "N"
	PRLow  PrivilegesRequired = "L"
	PRHigh PrivilegesRequired = "H"
)

type UserInteraction string
const (
	UINone  UserInteraction = "N"
	UIRequired UserInteraction = "R"
)

type Scope string
const (
	SUnchanged   Scope = "U"
	SChanged     Scope = "C"
)

type CIA string
const (
	CIANone     CIA = "N"
	CIALow      CIA = "L"
	CIAHigh     CIA = "H"
)

func Parse(raw string) (*Vector, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty CVSS vector")
	}

	v := &Vector{Raw: raw}

	parts := strings.Split(raw, "/")
	if len(parts) < 1 {
		return nil, fmt.Errorf("malformed CVSS vector")
	}

	verParts := strings.SplitN(parts[0], ":", 3)
	if len(verParts) >= 2 && strings.ToUpper(verParts[0]) == "CVSS" {
		v.Version = verParts[1]
		parts = parts[1:]
	}

	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(kv[0])
		val := kv[1]

		switch key {
		case "AV":
			v.AV = AttackVector(val)
		case "AC":
			v.AC = AttackComplexity(val)
		case "PR":
			v.PR = PrivilegesRequired(val)
		case "UI":
			v.UI = UserInteraction(val)
		case "S":
			v.S = Scope(val)
		case "C":
			v.C = CIA(val)
		case "I":
			v.I = CIA(val)
		case "A":
			v.A = CIA(val)
		}
	}

	return v, nil
}

func (v *Vector) Score() float64 {
	if v.Version == "" || v.Version[0] == '3' {
		return scoreV3(v)
	}
	return scoreV3(v)
}

func scoreV3(v *Vector) float64 {
	if v.AV == "" || v.AC == "" || v.PR == "" || v.UI == "" || v.S == "" || v.C == "" || v.I == "" || v.A == "" {
		return 0
	}

	av := avScore(v.AV)
	ac := acScore(v.AC)
	pr := prScore(v.PR, v.S)
	ui := uiScore(v.UI)
	s := scopeScore(v.S)
	c := ciScore(v.C)
	i := ciScore(v.I)
	a := ciScore(v.A)

	impact := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	var impactScore float64
	if s == 0 {
		impactScore = 6.42 * impact
	} else {
		impactScore = 7.52*(impact-0.029) - 3.25*math.Pow(impact-0.02, 15)
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impactScore <= 0 {
		return 0
	}

	var baseScore float64
	if s == 0 {
		baseScore = math.Min(impactScore+exploitability, 10)
	} else {
		baseScore = math.Min(1.08*(impactScore+exploitability), 10)
	}

	return math.Round(baseScore*10) / 10
}

func avScore(av AttackVector) float64 {
	switch av {
	case AVNetwork:
		return 0.85
	case AVAdjacent:
		return 0.62
	case AVLocal:
		return 0.55
	case AVPhysical:
		return 0.2
	}
	return 0
}

func acScore(ac AttackComplexity) float64 {
	switch ac {
	case ACLow:
		return 0.77
	case ACHigh:
		return 0.44
	}
	return 0
}

func prScore(pr PrivilegesRequired, s Scope) float64 {
	if s == SChanged {
		switch pr {
		case PRNone:
			return 0.85
		case PRLow:
			return 0.68
		case PRHigh:
			return 0.5
		}
	} else {
		switch pr {
		case PRNone:
			return 0.85
		case PRLow:
			return 0.62
		case PRHigh:
			return 0.27
		}
	}
	return 0
}

func uiScore(ui UserInteraction) float64 {
	switch ui {
	case UINone:
		return 0.85
	case UIRequired:
		return 0.62
	}
	return 0
}

func scopeScore(s Scope) float64 {
	if s == SChanged {
		return 1
	}
	return 0
}

func ciScore(c CIA) float64 {
	switch c {
	case CIANone:
		return 0
	case CIALow:
		return 0.22
	case CIAHigh:
		return 0.56
	}
	return 0
}

func SeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}
