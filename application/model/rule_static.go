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

package model

import (
	"github.com/webx-top/db"
	"github.com/webx-top/echo"

	"github.com/nging-plugins/firewallmanager/application/dbschema"
)

func NewRuleStatic(ctx echo.Context) *RuleStatic {
	return &RuleStatic{
		NgingFirewallRuleStatic: dbschema.NewNgingFirewallRuleStatic(ctx),
	}
}

type RuleStatic struct {
	*dbschema.NgingFirewallRuleStatic
}

func (r *RuleStatic) check() error {
	return nil
}

func (r *RuleStatic) Add() (interface{}, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.NgingFirewallRuleStatic.Insert()
}

func (r *RuleStatic) Edit(mw func(db.Result) db.Result, args ...interface{}) error {
	if err := r.check(); err != nil {
		return err
	}
	return r.NgingFirewallRuleStatic.Update(mw, args...)
}

func (r *RuleStatic) ListPage(cond *db.Compounds, sorts ...interface{}) ([]*dbschema.NgingFirewallRuleStatic, error) {
	err := r.NgingFirewallRuleStatic.ListPage(cond, sorts...)
	if err != nil {
		return nil, err
	}
	return r.Objects(), nil
}
