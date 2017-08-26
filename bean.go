package ruler

// Rule 最小单元，子规则
type Rule struct {
	Op  string      `json:"op"`  // 预算符
	Key string      `json:"key"` // 目标变量键名
	Val interface{} `json:"val"` // 目标变量子规则存值
	ID  int         `json:"id"`  // 子规则ID
	Msg string      `json:"msg"` // 该规则抛出的负提示
}

// Rules 规则，拥有逻辑表达式
type Rules struct {
	Rules []*Rule // 子规则集合
	Logic string  // 逻辑表达式，使用子规则ID运算表达
	Name  string  // 规则名称
	Msg   string  // 规则抛出的负提示
}

// RulesSet 规则集合
type RulesSet struct {
	RulesSet []*Rules
	Name     string
	Msg      string
}

// ValidOperators 有效
var ValidOperators = []string{"and", "or", "not"}

// Node 树节点
type Node struct {
	Expr       string  // 分割的logic表达式
	ChildrenOp string  // 孩子树之间的运算符: and, or, not
	Val        bool    // 节点值
	Computed   bool    // 节点值被计算过
	Leaf       bool    // 是否叶子节点
	Should     bool    // 为了Fit为true，此节点必须的值
	Blamed     bool    // 此节点为了Fit为true，有责任必须为某值
	Children   []*Node // 孩子树
}

type operator string

const (
	// OperatorAnd and
	OperatorAnd operator = "and"
	// OperatorOr or
	OperatorOr operator = "or"
	// OperatorNot not
	OperatorNot operator = "not"
)