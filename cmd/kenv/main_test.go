package main

import "testing"

func TestWantsHelp(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no help", args: []string{"run", "--env", ".env", "--", "echo", "hi"}, want: false},
		{name: "help first", args: []string{"--help", "run"}, want: true},
		{name: "help middle", args: []string{"run", "--help", "--env", ".env"}, want: true},
		{name: "help last", args: []string{"run", "--env", ".env", "--help"}, want: true},
		{name: "short help", args: []string{"run", "-h"}, want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantsHelp(tc.args); got != tc.want {
				t.Fatalf("wantsHelp(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestHasRunShape(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want bool
	}{
		{name: "valid", args: []string{"--env", ".env", "--", "echo", "hi"}, want: true},
		{name: "valid with inherit env", args: []string{"--inherit-env", "--env", ".env", "--", "echo", "hi"}, want: true},
		{name: "missing env flag", args: []string{".env", "--", "echo", "hi"}, want: false},
		{name: "empty env path", args: []string{"--env", "", "--", "echo", "hi"}, want: false},
		{name: "missing separator", args: []string{"--env", ".env", "echo", "hi"}, want: false},
		{name: "missing command", args: []string{"--env", ".env", "--"}, want: false},
		{name: "inherit env missing rest", args: []string{"--inherit-env", "--env", ".env"}, want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasRunShape(tc.args); got != tc.want {
				t.Fatalf("hasRunShape(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want int
	}{
		{name: "no args", args: nil, want: 2},
		{name: "top level help", args: []string{"help"}, want: 0},
		{name: "unknown command", args: []string{"wat"}, want: 2},
		{name: "init help", args: []string{"init", "--help"}, want: 0},
		{name: "run help", args: []string{"run", "--help"}, want: 0},
		{name: "scope help", args: []string{"scope", "--help"}, want: 0},
		{name: "run invalid shape", args: []string{"run", "--env", ".env"}, want: 2},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}
