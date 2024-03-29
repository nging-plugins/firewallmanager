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

package cmdutils

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"

	"github.com/admpub/null"
)

type RowInfo struct {
	RowNo  uint
	Handle null.Uint
	Row    string
}

func (r RowInfo) HasHandleID() bool {
	return r.Handle.Valid
}

func (r RowInfo) IsZero() bool {
	return !r.Handle.Valid && r.Handle.Uint == 0 && r.RowNo == 0 && len(r.Row) == 0
}

func (r RowInfo) GetHandleID() uint {
	return r.Handle.Uint
}

func (r RowInfo) String() string {
	return r.Row
}

type readData struct {
	rows    []RowInfo
	hasMore bool
	offset  uint
	err     error
}

func LineSeeker(r io.Reader, startOffset, limit uint, parser func(uint, string) (RowInfo, error)) (rows []RowInfo, hasMore bool, index uint, err error) {
	maxNo := startOffset + limit
	var size uint
	s := bufio.NewScanner(r)
	rows = make([]RowInfo, 0, limit)
	for s.Scan() {
		if startOffset > index {
			index++
			continue
		}
		index++
		if size >= maxNo {
			hasMore = true
			err = ErrCmdForcedExit
			return
		}
		t := s.Text()
		t = strings.TrimSpace(t)
		rowInfo, perr := parser(index, t)
		if err != nil {
			err = perr
			return
		}
		if len(rowInfo.Row) == 0 {
			continue
		}
		rows = append(rows, rowInfo)
		size++
	}
	return
}

func RecvCmdOutputs(startOffset, limit uint,
	cmdBin string, cmdArgs []string,
	parser func(uint, string) (RowInfo, error),
) (rows []RowInfo, hasMore bool, offset uint, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	res := make(chan *readData)
	err = RunCmdWithCallback(ctx, cmdBin, cmdArgs, func(cmd *exec.Cmd) error {
		r, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		go func() {
			rd := &readData{}
			rd.rows, rd.hasMore, rd.offset, rd.err = LineSeeker(r, startOffset, limit, parser)
			if rd.err != nil {
				cancel()
			}
			res <- rd
			r.Close()
		}()
		return nil
	})
	rd := <-res
	rows = rd.rows
	hasMore = rd.hasMore
	offset = rd.offset
	if rd.err == nil {
		return
	}
	if !errors.Is(rd.err, ErrCmdForcedExit) {
		err = rd.err
		return
	}
	if err != nil && (strings.Contains(err.Error(), `signal: killed`) || errors.Is(err, context.Canceled)) {
		err = nil
	}
	return
}
