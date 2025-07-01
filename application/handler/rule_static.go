/*
   Nging is a toolbox for webmasters
   Copyright (C) 2018-present  Wenhui Shen <swh@admpub.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package handler

import (
	"bufio"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/admpub/log"
	"github.com/webx-top/com"
	"github.com/webx-top/db"
	"github.com/webx-top/echo"
	"github.com/webx-top/echo/code"
	"github.com/webx-top/echo/middleware/bytes"
	"github.com/webx-top/echo/param"

	"github.com/coscms/webcore/library/backend"
	"github.com/coscms/webcore/library/common"
	"github.com/coscms/webcore/library/errorslice"
	"github.com/nging-plugins/firewallmanager/application/dbschema"
	"github.com/nging-plugins/firewallmanager/application/library/enums"
	"github.com/nging-plugins/firewallmanager/application/library/firewall"
	"github.com/nging-plugins/firewallmanager/application/library/netutils"
	"github.com/nging-plugins/firewallmanager/application/model"
)

func ruleStaticSetFormData(c echo.Context) {
	c.Set(`types`, enums.Types.Slice())
	c.Set(`directions`, enums.Directions.Slice())
	c.Set(`ipProtocols`, enums.IPProtocols.Slice())
	c.Set(`netProtocols`, enums.NetProtocols.Slice())
	c.Set(`actions`, enums.Actions.Slice())
	c.Set(`stateList`, enums.StateList)
	c.Set(`tablesChains`, enums.TablesChains)
	c.Set(`chainParams`, enums.ChainParams)
}

func ruleStaticIndex(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	cond := db.NewCompounds()
	sorts := common.Sorts(ctx, m.NgingFirewallRuleStatic, `position`, `id`)
	list, err := m.ListPage(cond, sorts...)
	ctx.Set(`listData`, list)
	ctx.Set(`firewallBackend`, firewall.GetBackend())
	return ctx.Render(`firewall/rule/static`, common.Err(ctx, err))
}

func ruleStaticGetFirewallPosition(m *model.RuleStatic, row *dbschema.NgingFirewallRuleStatic, excludeOther ...uint) (uint, error) {
	next, err := m.NextRow(row.Type, row.Direction, row.IpVersion, row.Position, row.Id, excludeOther...)
	if err != nil {
		if errors.Is(err, db.ErrNoMoreRows) {
			err = nil
		}
		return 0, err
	}
	var pos uint
	pos, err = firewall.FindPositionByID(row.IpVersion, row.Type, row.Direction, next.Id)
	if err != nil {
		return 0, err
	}
	if pos == 0 {
		excludeOther = append(excludeOther, row.Id)
		return ruleStaticGetFirewallPosition(m, next, excludeOther...)
	}
	return pos, err
}

func ruleStaticAdd(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	var err error
	if ctx.IsPost() {
		err = ctx.MustBind(m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		m.State = strings.Join(param.StringSlice(ctx.FormValues(`state`)).Filter().String(), `,`)
		_, err = m.Add()
		if err != nil {
			goto END
		}
		rule := m.AsRule()
		rule.Number, err = ruleStaticGetFirewallPosition(m, m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		if rule.Number > 0 {
			err = firewall.Insert(rule)
		} else {
			err = firewall.Append(rule)
		}
		if err != nil {
			goto END
		}
		setStaticRuleLastModifyTime(time.Now())
		return ctx.Redirect(backend.URLFor(`/firewall/rule/static`))
	} else {
		id := ctx.Formx(`copyId`).Uint()
		if id > 0 {
			err = m.Get(nil, db.Cond{`id`: id})
			if err == nil {
				echo.StructToForm(ctx, m.NgingFirewallRuleStatic, ``, echo.LowerCaseFirstLetter)
				ctx.Request().Form().Set(`id`, `0`)
			}
		}
	}

END:
	ctx.Set(`activeURL`, `/firewall/rule/static`)
	ctx.Set(`title`, ctx.T(`添加规则`))
	ctx.Set(`states`, param.StringSlice(strings.Split(m.State, `,`)).Filter().String())
	ruleStaticSetFormData(ctx)
	return ctx.Render(`firewall/rule/static_edit`, common.Err(ctx, err))
}

func ruleStaticEdit(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	id := ctx.Formx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err != nil {
		return err
	}
	if ctx.IsPost() {
		old := *m.NgingFirewallRuleStatic
		err = ctx.MustBind(m.NgingFirewallRuleStatic)
		if err != nil {
			goto END
		}
		m.State = strings.Join(param.StringSlice(ctx.FormValues(`state`)).Filter().String(), `,`)
		m.Id = id
		err = m.Edit(nil, `id`, id)
		if err != nil {
			goto END
		}
		oldRule := model.AsRule(&old)
		err = firewall.Delete(oldRule)
		if err != nil {
			goto END
		}
		setStaticRuleLastModifyTime(time.Now())
		if m.Disabled != `Y` {
			rule := m.AsRule()
			rule.Number, err = ruleStaticGetFirewallPosition(m, m.NgingFirewallRuleStatic)
			if err != nil {
				goto END
			}
			if rule.Number > 0 {
				err = firewall.Insert(rule)
			} else {
				err = firewall.Append(rule)
			}
			if err != nil {
				goto END
			}
		}
		return ctx.Redirect(backend.URLFor(`/firewall/rule/static`))
	} else if ctx.IsAjax() {
		disabled := ctx.Query(`disabled`)
		if len(disabled) > 0 {
			if !common.IsBoolFlag(disabled) {
				return ctx.NewError(code.InvalidParameter, ``).SetZone(`disabled`)
			}
			data := ctx.Data()
			if m.Disabled == disabled {
				data.SetError(ctx.NewError(code.DataNotChanged, `状态没有改变`))
				return ctx.JSON(data)
			}
			m.Disabled = disabled
			err = m.UpdateField(nil, `disabled`, disabled, db.Cond{`id`: id})
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			rule := m.AsRule()
			if m.Disabled == `Y` {
				err = firewall.Delete(rule)
			} else {
				rule.Number, err = ruleStaticGetFirewallPosition(m, m.NgingFirewallRuleStatic)
				if err != nil {
					goto END
				}
				if rule.Number > 0 {
					err = firewall.Insert(rule)
				} else {
					err = firewall.Append(rule)
				}
			}
			if err != nil {
				data.SetError(err)
				return ctx.JSON(data)
			}
			data.SetInfo(ctx.T(`操作成功`))
			return ctx.JSON(data)
		}
	}
	echo.StructToForm(ctx, m.NgingFirewallRuleStatic, ``, echo.LowerCaseFirstLetter)

END:
	ctx.Set(`activeURL`, `/firewall/rule/static`)
	ctx.Set(`title`, ctx.T(`修改规则`))
	ctx.Set(`states`, param.StringSlice(strings.Split(m.State, `,`)).Filter().String())
	ruleStaticSetFormData(ctx)
	return ctx.Render(`firewall/rule/static_edit`, common.Err(ctx, err))
}

func ruleStaticDelete(ctx echo.Context) error {
	m := model.NewRuleStatic(ctx)
	id := ctx.Formx(`id`).Uint()
	err := m.Get(nil, `id`, id)
	if err == nil {
		err = m.Delete(nil, `id`, id)
		if err == nil {
			rule := m.AsRule()
			err = firewall.Delete(rule)
		}
	}
	if err == nil {
		setStaticRuleLastModifyTime(time.Now())
		common.SendOk(ctx, ctx.T(`删除成功`))
	} else {
		common.SendErr(ctx, err)
	}
	return ctx.Redirect(backend.URLFor(`/firewall/rule/static`))
}

func ruleStaticApply(ctx echo.Context) error {
	if !firewallReady() {
		return ctx.NewError(code.Unsupported, `没有找到支持的防火墙程序`)
	}
	firewall.ResetEngine()
	firewall.Clear(`all`)
	err := applyNgingRule(ctx)
	if err != nil {
		goto END
	}
	err = firewall.AddDefault(`all`)
	if err != nil {
		goto END
	}
	err = applyStaticRule(ctx)
	if err != nil {
		goto END
	}

END:
	if err == nil {
		common.SendOk(ctx, ctx.T(`规则应用成功`))
	} else {
		common.SendErr(ctx, err)
	}
	return ctx.Redirect(backend.URLFor(`/firewall/rule/static`))
}

func ruleStaticBan(ctx echo.Context) error {
	if !firewallReady() {
		return ctx.NewError(code.Unsupported, `没有找到支持的防火墙程序`)
	}
	fileMaxSize := 50 * int64(bytes.MB)
	fileExtensions := []string{`.txt`}
	var err error
	if ctx.IsPost() {
		ctx.Request().MultipartForm()
		ips := ctx.Form(`ips`)
		ips = strings.TrimSpace(ips)
		dur := ctx.Formx(`expire`).Uint()
		unit := ctx.Form(`unit`)
		var expire time.Duration
		switch unit {
		case `h`: //小时
			expire = time.Hour * time.Duration(dur)
		case `d`: //天
			expire = time.Hour * 24 * time.Duration(dur)
		case `m`: //月
			now := time.Now()
			expire = now.AddDate(0, int(dur), 0).Sub(now)
		case `y`: //年
			now := time.Now()
			expire = now.AddDate(int(dur), 0, 0).Sub(now)
		default:
			return ctx.NewError(code.InvalidParameter, `单位无效`).SetZone(`unit`)
		}
		if expire <= 0 {
			expire = time.Hour * 24
		}
		var ipv4 []string
		var ipv6 []string
		errs := errorslice.New()
		for _, ip := range strings.Split(ips, com.StrLF) {
			ip = strings.TrimSpace(ip)
			if len(ip) == 0 {
				continue
			}
			ipVer, err := netutils.ValidateIP(ctx, ip)
			if err != nil {
				errs.Add(err)
				continue
			}
			if ipVer == 4 {
				ipv4 = append(ipv4, ip)
			} else if ipVer == 6 {
				ipv6 = append(ipv6, ip)
			} else {
				log.Errorf(`invalid IP: %s`, ip)
			}
		}

		if fileSrc, fileHdr, fileErr := ctx.Request().FormFile(`file`); fileErr == nil {
			ext := path.Ext(fileHdr.Filename)
			ext = strings.ToLower(ext)
			if !com.InSlice(ext, fileExtensions) {
				errs.Add(fmt.Errorf(ctx.T(`文件上传失败。仅支持扩展名为“.txt”的文本文件`)))
			} else if fileHdr.Size > fileMaxSize {
				errs.Add(fmt.Errorf(ctx.T(`文件上传失败。文件太大，不能超过 50MB`)))
			} else {
				sc := bufio.NewScanner(fileSrc)
				for sc.Scan() {
					ip := sc.Text()
					ip = strings.TrimSpace(ip)
					if len(ip) == 0 {
						continue
					}
					ipVer, err := netutils.ValidateIP(ctx, ip)
					if err != nil {
						log.Error(err.Error())
						continue
					}
					if ipVer == 4 {
						ipv4 = append(ipv4, ip)
					} else if ipVer == 6 {
						ipv6 = append(ipv6, ip)
					} else {
						log.Errorf(`invalid IP: %s`, ip)
					}
				}
			}
			fileSrc.Close()
		}
		if len(ipv4) == 0 && len(ipv6) == 0 {
			common.SendFail(ctx, ctx.T(`IP 数据为空`))
			goto END
		}
		if len(ipv4) > 0 {
			if err = firewall.Engine(`4`).Ban(ipv4, expire); err != nil {
				return err
			}
		}
		if len(ipv6) > 0 {
			if err = firewall.Engine(`6`).Ban(ipv6, expire); err != nil {
				return err
			}
		}
		err = errs.ToError()
		if err != nil {
			common.SendOk(ctx, ctx.T(`操作成功。但有部分错误：%s`, com.Nl2br(err.Error())))
		} else {
			common.SendOk(ctx, ctx.T(`操作成功`))
			return ctx.Redirect(backend.URLFor(`/firewall/rule/static_ban`))
		}
	}

END:
	ctx.Set(`activeURL`, `/firewall/rule/static`)
	ctx.Set(`title`, ctx.T(`临时封IP`))
	ctx.Set(`fileMaxSize`, fileMaxSize)
	ctx.Set(`fileExtensions`, fileExtensions)
	return ctx.Render(`firewall/rule/static_ban`, common.Err(ctx, err))
}
