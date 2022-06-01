package lib

import (
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_xray/models"
	dModels "github.com/inbug-team/SweetBabyScan/models"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ceYeApi    = "f21b6b01158371fbd51ff7700a800431"
	ceYeDomain = "u4toha.ceye.io"
)

type Task struct {
	Req *http.Request
	Poc *dModels.DataPocXray
}

func ExecutePoc(oReq *http.Request, p *dModels.DataPocXray) (bool, error, string) {
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	if len(p.Sets) > 0 {
		setMap := make(map[string]string)
		for k := range p.Sets {
			setMap[k] = p.Sets[k][0]
		}
		c.UpdateCompileOptions(setMap)
	}
	env, err := NewEnv(&c)
	if err != nil {
		//fmt.Printf("[-] %s environment creation error: %s\n", p.Name, err)
		return false, err, ""
	}
	req, err := ParseRequest(oReq)
	if err != nil {
		//fmt.Printf("[-] %s ParseRequest error: %s\n", p.Name, err)
		return false, err, ""
	}
	variableMap := make(map[string]interface{})
	variableMap["request"] = req

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	keys := make([]string, 0)
	keys1 := make([]string, 0)
	for k := range p.Set {
		if strings.Contains(strings.ToLower(p.Set[k]), "random") && strings.Contains(strings.ToLower(p.Set[k]), "(") {
			keys = append(keys, k) //优先放入调用random系列函数的变量
		} else {
			keys1 = append(keys1, k)
		}
	}
	sort.Strings(keys)
	sort.Strings(keys1)
	keys = append(keys, keys1...)
	for _, k := range keys {
		expression := p.Set[k]
		if k != "payload" {
			if expression == "newReverse()" {
				variableMap[k] = newReverse()
				continue
			}
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				variableMap[k] = expression
				continue
			}
			switch value := out.Value().(type) {
			case *models.UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = int(value)
			case []uint8:
				variableMap[k] = fmt.Sprintf("%s", out)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	if p.Set["payload"] != "" {
		out, err := Evaluate(env, p.Set["payload"], variableMap)
		if err != nil {
			return false, err, ""
		}
		variableMap["payload"] = fmt.Sprintf("%v", out)
	}

	setsLen := 0
	hasPayload := false
	var setsKeys []string
	if len(p.Sets) > 0 {
		for _, rule := range p.Rules {
			for k := range p.Sets {
				if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						hasPayload = true
					}
					setsLen++
					setsKeys = append(setsKeys, k)
					continue
				}
				for k2 := range rule.Headers {
					if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
						if strings.Contains(k, "payload") {
							hasPayload = true
						}
						setsLen++
						setsKeys = append(setsKeys, k)
						continue
					}
				}
			}
		}
	}

	success := false
	//爆破模式,比如tomcat弱口令
	if setsLen > 0 {
		if hasPayload {
			success, err = clusterPoc1(oReq, p, variableMap, req, env, setsKeys)
		} else {
			success, err = clusterPoc(oReq, p, variableMap, req, env, setsLen, setsKeys)
		}
		return success, nil, ""
	}

	DealWithRule := func(rule dModels.Rules) (bool, error) {
		Headers := cloneMap(rule.Headers)
		var (
			flag, ok bool
		)
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range Headers {
				if !strings.Contains(v2, "{{"+k1+"}}") {
					continue
				}
				Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
		req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
		newRequest.Header = oReq.Header.Clone()
		for k, v := range Headers {
			newRequest.Header.Set(k, v)
		}
		resp, err := DoRequest(newRequest, rule.FollowRedirects)
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp
		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			} else {
				return false, nil
			}
		}
		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}

		//如果false不继续执行后续rule
		// 如果最后一步执行失败，就算前面成功了最终依旧是失败
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		return flag, nil
	}

	DealWithRules := func(rules []dModels.Rules) bool {
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)

			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
		}
		return successFlag
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else {
		for name, rules := range p.Groups {
			success = DealWithRules(rules)
			if success {
				return success, nil, name
			}
		}
	}

	return success, nil, ""
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				paramsMap[name] = result[i]
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *models.Reverse {
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := RandomStr(randSource, letters, 8)
	if true {
		//默认不开启dns解析
		return &models.Reverse{}
	}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceYeDomain)
	u, _ := url.Parse(urlStr)
	return &models.Reverse{
		Url:                ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func clusterPoc(oReq *http.Request, p *dModels.DataPocXray, variableMap map[string]interface{}, req *models.Request, env *cel.Env, sLen int, keys []string) (success bool, err error) {
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		n := 0
		for k := range p.Sets {
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					n++
					continue
				}
			}
		}
		if n == 0 {
			success, err = clusterSend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}

		if sLen == 1 {
		look1:
			for _, var1 := range p.Sets[keys[0]] {
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
				success, err = clusterSend(oReq, variableMap, req, env, rule1)
				if err != nil {
					return false, err
				}
				if success == true {
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if sLen == 2 {
		look2:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
					success, err = clusterSend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if sLen == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						success, err = clusterSend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func clusterPoc1(oReq *http.Request, p *dModels.DataPocXray, variableMap map[string]interface{}, req *models.Request, env *cel.Env, keys []string) (success bool, err error) {
	setMap := make(map[string]interface{})
	for k := range p.Sets {
		setMap[k] = p.Sets[k][0]
	}
	setMapBak := cloneMap1(setMap)
	for _, rule := range p.Rules {
		for k1, v1 := range variableMap {
			if IsContain(keys, k1) {
				continue
			}
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range rule.Headers {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		}

		var varSet []string
		var varPay []string
		n := 0
		for k := range p.Sets {
			// 1. 如果rule中需要修改 {{k}} 如username、payload
			if strings.Contains(rule.Body, "{{"+k+"}}") || strings.Contains(rule.Path, "{{"+k+"}}") {
				if strings.Contains(k, "payload") {
					varPay = append(varPay, k)
				} else {
					varSet = append(varSet, k)
				}
				n++
				continue
			}
			for k2 := range rule.Headers {
				if strings.Contains(rule.Headers[k2], "{{"+k+"}}") {
					if strings.Contains(k, "payload") {
						varPay = append(varPay, k)
					} else {
						varSet = append(varSet, k)
					}
					n++
					continue
				}
			}
		}

		for _, key := range varPay {
			v := fmt.Sprintf("%s", setMap[key])
			for k := range p.Sets {
				if strings.Contains(v, k) {
					if !IsContain(varSet, k) && !IsContain(varPay, k) {
						varSet = append(varSet, k)
					}
				}
			}
		}
		if n == 0 {
			success, err = clusterSend(oReq, variableMap, req, env, rule)
			if err != nil {
				return false, err
			}
			if success == false {
				break
			}
		}
		if len(varSet) == 1 {
		look1:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varSet[0]] {
				setMap := cloneMap1(setMapBak)
				setMap[varSet[0]] = var1
				evalSet(env, setMap)
				rule1 := cloneRules(rule)
				for k2, v2 := range rule1.Headers {
					rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varSet[0]+"}}", var1)
					for _, key := range varPay {
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
				}
				rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varSet[0]+"}}", var1)
				rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varSet[0]+"}}", var1)
				for _, key := range varPay {
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
				}
				success, err = clusterSend(oReq, variableMap, req, env, rule)
				if err != nil {
					return false, err
				}

				if success == true {
					break look1
				}
			}
			if success == false {
				break
			}
		}

		if len(varSet) == 2 {
		look2:
			//	(var1 tomcat ,keys[0] username)
			for _, var1 := range p.Sets[varSet[0]] { //username
				for _, var2 := range p.Sets[varSet[1]] { //password
					setMap := cloneMap1(setMapBak)
					setMap[varSet[0]] = var1
					setMap[varSet[1]] = var2
					evalSet(env, setMap)
					rule1 := cloneRules(rule)
					for k2, v2 := range rule1.Headers {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+varSet[0]+"}}", var1)
						rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+varSet[1]+"}}", var2)
						for _, key := range varPay {
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
					}
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varSet[0]+"}}", var1)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varSet[0]+"}}", var1)
					rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+varSet[1]+"}}", var2)
					rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+varSet[1]+"}}", var2)
					for _, key := range varPay {
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
					}
					success, err = clusterSend(oReq, variableMap, req, env, rule1)
					if err != nil {
						return false, err
					}
					if success == true {
						break look2
					}
				}
			}
			if success == false {
				break
			}
		}

		if len(varSet) == 3 {
		look3:
			for _, var1 := range p.Sets[keys[0]] {
				for _, var2 := range p.Sets[keys[1]] {
					for _, var3 := range p.Sets[keys[2]] {
						setMap := cloneMap1(setMapBak)
						setMap[varSet[0]] = var1
						setMap[varSet[1]] = var2
						evalSet(env, setMap)
						rule1 := cloneRules(rule)
						for k2, v2 := range rule1.Headers {
							rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+keys[0]+"}}", var1)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[1]+"}}", var2)
							rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+keys[2]+"}}", var3)
							for _, key := range varPay {
								rule1.Headers[k2] = strings.ReplaceAll(rule1.Headers[k2], "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							}
						}
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[0]+"}}", var1)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[0]+"}}", var1)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[1]+"}}", var2)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[1]+"}}", var2)
						rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+keys[2]+"}}", var3)
						rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+keys[2]+"}}", var3)
						for _, key := range varPay {
							rule1.Path = strings.ReplaceAll(strings.TrimSpace(rule1.Path), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
							rule1.Body = strings.ReplaceAll(strings.TrimSpace(rule1.Body), "{{"+key+"}}", fmt.Sprintf("%v", setMap[key]))
						}
						success, err = clusterSend(oReq, variableMap, req, env, rule)
						if err != nil {
							return false, err
						}
						if success == true {
							break look3
						}
					}
				}
			}
			if success == false {
				break
			}
		}
	}
	return success, nil
}

func clusterSend(oReq *http.Request, variableMap map[string]interface{}, req *models.Request, env *cel.Env, rule dModels.Rules) (bool, error) {
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}
	// 某些poc没有区分path和query，需要处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
	req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

	newRequest, _ := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	resp, err := DoRequest(newRequest, rule.FollowRedirects)
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// 先判断响应页面是否匹配search规则
	if rule.Search != "" {
		result := doSearch(strings.TrimSpace(rule.Search), string(resp.Body))
		if result != nil && len(result) > 0 { // 正则匹配成功
			for k, v := range result {
				variableMap[k] = v
			}
			//return false, nil
		} else {
			return false, nil
		}
	}

	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		return false, err
	}

	if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
		return false, err // 如果最后一步执行失败，就算前面成功了最终依旧是失败
	}
	return true, err
}

func cloneRules(tags dModels.Rules) dModels.Rules {
	cloneTags := dModels.Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func cloneMap1(tags map[string]interface{}) map[string]interface{} {
	cloneTags := make(map[string]interface{})
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func evalSet(env *cel.Env, variableMap map[string]interface{}) {
	for k := range variableMap {
		expression := fmt.Sprintf("%v", variableMap[k])
		if !strings.Contains(k, "payload") {
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				variableMap[k] = expression
				continue
			}
			switch value := out.Value().(type) {
			case *models.UrlType:
				variableMap[k] = UrlTypeToString(value)
			case int64:
				variableMap[k] = fmt.Sprintf("%v", value)
			case []uint8:
				variableMap[k] = fmt.Sprintf("%v", out)
			default:
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}

	for k := range variableMap {
		expression := fmt.Sprintf("%v", variableMap[k])
		if strings.Contains(k, "payload") {
			out, err := Evaluate(env, expression, variableMap)
			if err != nil {
				variableMap[k] = expression
			} else {
				variableMap[k] = fmt.Sprintf("%v", out)
			}
		}
	}
}
