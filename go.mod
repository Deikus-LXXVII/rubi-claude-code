module github.com/Deikus-LXXVII/rubi-claude-code

go 1.26.4

require github.com/Deikus-LXXVII/rubi v0.10.2

require github.com/google/jsonschema-go v0.4.3 // indirect

// Needs the core branch citri/claude-home-capability (home "claude", approval.wait) until it is released.
replace github.com/Deikus-LXXVII/rubi => ../rubi
