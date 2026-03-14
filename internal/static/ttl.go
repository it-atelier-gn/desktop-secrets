package static

type TTLOption struct {
	Label     string
	Minutes   int
	IsDefault bool
}

const DefaultTTL = 15

var TTLOptions = []TTLOption{
	{Label: "5 minutes", Minutes: 5, IsDefault: false},
	{Label: "15 minutes (default)", Minutes: 15, IsDefault: true},
	{Label: "1 hour", Minutes: 60, IsDefault: false},
	{Label: "2 hours", Minutes: 120, IsDefault: false},
	{Label: "4 hours", Minutes: 240, IsDefault: false},
}
