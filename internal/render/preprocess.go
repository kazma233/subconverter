package render

import (
	"regexp"
	"sort"
	"strings"

	"subconv/internal/model"
)

// ApplySubOverrides 在渲染前应用 /sub 参数带来的节点级修改：
//
//	FolderPrefix → 节点名前缀
//	RenameRule → 正则替换节点名
//	RemoveEmoji → 先剥掉节点名中原有的 UTF-8 emoji
//	AddEmoji → 按默认 emoji 规则表给节点名加前缀国旗
//	FilterDeprecated → 过滤废弃加密 (SS chacha20)
//	Sort → 节点名字典序升序
//	UDP / TCPFastOpen / SkipCertVerify → 当 Config 三态非 nil 时覆盖所有节点
//
// 返回新的切片（就地修改字段值 + 必要时创建新切片实现过滤）。
func ApplySubOverrides(nodes []model.Proxy, cfg *Config) []model.Proxy {
	if cfg == nil {
		return nodes
	}

	// 0) folder 前缀：先加，后面 emoji/rename 在前缀基础上继续改
	if cfg.FolderPrefix != "" {
		prefix := strings.TrimSpace(cfg.FolderPrefix) + " - "
		for i := range nodes {
			nodes[i].Name = prefix + nodes[i].Name
		}
	}

	// 1) 自定义 Rename
	for _, r := range cfg.RenameRule {
		if r.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			// 编译失败：跳过该规则，保持克制（不扩展范围到额外错误处理）
			continue
		}
		repl := r.Replacement
		for i := range nodes {
			if re.MatchString(nodes[i].Name) {
				nodes[i].Name = re.ReplaceAllString(nodes[i].Name, repl)
			}
		}
	}

	// 2) 剥 emoji：remove_emoji=true 或 emoji=true（后者=先去旧再加新）
	needRemove := (cfg.RemoveEmoji != nil && *cfg.RemoveEmoji) ||
		(cfg.AddEmoji != nil && *cfg.AddEmoji)
	if needRemove {
		for i := range nodes {
			nodes[i].Name = stripEmoji(nodes[i].Name)
		}
	}

	// 3) 加 emoji
	if cfg.AddEmoji != nil && *cfg.AddEmoji {
		for i := range nodes {
			if emoji := defaultEmojiFor(nodes[i].Name); emoji != "" {
				nodes[i].Name = emoji + " " + nodes[i].Name
			}
		}
	}

	// 4) 三态覆盖：Config 非 nil 指针强制覆盖；nil 保持节点自身声明
	for i := range nodes {
		if cfg.UDP != nil {
			v := *cfg.UDP
			nodes[i].UDP = &v
		}
		if cfg.TCPFastOpen != nil {
			v := *cfg.TCPFastOpen
			nodes[i].TCPFastOpen = &v
		}
		if cfg.SkipCertVerify != nil {
			v := *cfg.SkipCertVerify
			nodes[i].SkipCertVerify = &v
		}
	}

	// 5) 过滤废弃节点：仅 SS 的 chacha20（mihomo 已移除）
	if cfg.FilterDeprecated {
		out := nodes[:0]
		for _, n := range nodes {
			if n.Type == model.TypeSS && strings.EqualFold(n.Cipher, "chacha20") {
				continue
			}
			out = append(out, n)
		}
		nodes = out
	}

	// 6) 排序：按节点名字典序升序（C++ sort_flag=true 默认行为）
	if cfg.Sort {
		sort.SliceStable(nodes, func(i, j int) bool {
			return nodes[i].Name < nodes[j].Name
		})
	}

	return nodes
}

// defaultEmojiRules 默认 emoji→关键词映射（克制版最小集合：常见机场区域/用途标签）。
// 非锚定包含匹配，命中第一个即返回。
var defaultEmojiRules = []struct {
	emoji     string
	keywords  []string
}{
	{"🇭🇰", []string{"香港", "hongkong", "hong kong", "hk", "hkg"}},
	{"🇯🇵", []string{"日本", "japan", "tokyo", "jp"}},
	{"🇸🇬", []string{"新加坡", "singapore", "sg", "sin"}},
	{"🇺🇸", []string{"美国", "美西", "美东", "usa", "us", "america", "los", "silicon", "san jose", "new york", "seattle"}},
	{"🇹🇼", []string{"台湾", "台北", "taiwan", "tw", "taipei"}},
	{"🇰🇷", []string{"韩国", "首尔", "korea", "kr", "seoul"}},
	{"🇬🇧", []string{"英国", "伦敦", "uk", "britain", "england", "london"}},
	{"🇩🇪", []string{"德国", "德", "germany", "de", "frankfurt"}},
	{"🇳🇱", []string{"荷兰", "阿姆斯特丹", "netherlands", "nl", "ams"}},
	{"🇫🇷", []string{"法国", "法", "france", "paris", "fra"}},
	{"🇨🇦", []string{"加拿大", "canada", "ca", "toronto", "vancouver"}},
	{"🇦🇺", []string{"澳洲", "澳大利亚", "sydney", "aus", "australia", "澳"}},
	{"🇹🇭", []string{"泰国", "thailand", "th", "bangkok"}},
	{"🇻🇳", []string{"越南", "vietnam", "vn", "hcm", "saigon"}},
	{"🇮🇳", []string{"印度", "india", "in", "mumbai"}},
	{"🇵🇭", []string{"菲律宾", "philippines", "ph", "manila"}},
	{"🇲🇾", []string{"马来", "malaysia", "my", "kuala"}},
	{"🇷🇺", []string{"俄", "russia", "ru", "moscow"}},
	{"🇦🇪", []string{"阿联酋", "迪拜", "uae", "dubai"}},
	{"🇧🇷", []string{"巴西", "brazil", "br", "saopaulo"}},
	{"🍿", []string{"奈飞", "netflix", "nf", "网飞"}},
	{"📺", []string{"disney", "disney+", "迪士尼", "hbo", "hulu"}},
	{"🤖", []string{"chatgpt", "gpt", "openai", "claude", "ai"}},
}

// defaultEmojiFor 返回名称命中的默认 emoji；空串表示不添加。
func defaultEmojiFor(name string) string {
	lower := strings.ToLower(name)
	for _, r := range defaultEmojiRules {
		for _, kw := range r.keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return r.emoji
			}
		}
	}
	return ""
}

// stripEmoji 移除字符串中常见的 emoji 字符（UTF-8 0xF0 0x9F/0xA0 开头四字节序列
// + 常见国旗 🇦🇿 等双字母序列），用于 remove_old_emoji。
// 实现比 C++ 宽：删除所有 Unicode 符号类（So 类别）和 Regional Indicator 字母对。
func stripEmoji(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		// Regional Indicator A-Z（0x1F1E6 起）：国旗两两一组，成对跳过
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if i+1 < len(runes) && runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
				i++
				continue
			}
			continue
		}
		// So 类别（Misc Symbol / Pictograph / Dingbat / Emoticons）
		if (r >= 0x2600 && r <= 0x27BF) || // Misc symbols/Dingbats
			(r >= 0x1F300 && r <= 0x1F5FF) || // Misc symbols & pictographs
			(r >= 0x1F600 && r <= 0x1F64F) || // Emoticons
			(r >= 0x1F680 && r <= 0x1F6FF) || // Transport & map
			(r >= 0x1F700 && r <= 0x1F9FF) || // Alchemical/Suppl Symbols/Gestures
			(r >= 0x1FA00 && r <= 0x1FAFF) || // Symbols extended
			(r == 0x200D || r == 0xFE0F) { // ZWJ / variation selector
			continue
		}
		b.WriteRune(r)
	}
	// 清理多重空格
	out := strings.TrimSpace(b.String())
	for strings.Contains(out, "  ") {
		out = strings.ReplaceAll(out, "  ", " ")
	}
	return out
}
