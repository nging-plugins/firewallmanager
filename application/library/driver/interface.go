package driver

type Driver interface {
	RuleFrom(rule *Rule) []string
	Enabled(on bool) error
	Reset() error
	Import(wfwFile string) error
	Export(wfwFile string) error
	Insert(pos int, rule *Rule) error
	Append(rule *Rule) error
	Update(pos int, rule *Rule) error
	Delete(rule *Rule) error
	Exists(rule *Rule) (bool, error)
	Stats(table, chain string) ([]map[string]string, error)
	List(table, chain string) ([]*Rule, error)
}
