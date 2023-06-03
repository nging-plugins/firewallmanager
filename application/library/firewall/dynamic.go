package firewall

import "github.com/webx-top/echo"

var DynamicRuleSources = echo.NewKVData().
	Add(`file`, `日志文件(使用tail)`, echo.KVOptHKV(`path`, `文件路径`)).
	Add(`systemd`, `服务日志(使用journalctl)`, echo.KVOptHKV(`service`, `服务名`)).
	Add(`kernel`, `系统日志(使用journalctl)`).
	Add(`process`, `命令`, echo.KVOptHKV(`name`, `可执行文件`), echo.KVOptHKV(`args`, `参数`))

var DynamicRuleActions = echo.NewKVData().
	Add(`ban`, `禁止访问`, echo.KVOptHKV(`duration`, `时长`)).
	Add(`log`, `记录日志`, echo.KVOptHKV(`extended`, `是否记录附加信息`))
