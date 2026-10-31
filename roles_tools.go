package main

// The Bot tools for agent roles (claude_code_role_*). Who is asking comes only from Rubi's verified Bot name
// (rubi_verified_agent), as in the other tools; no argument names a Bot. Every writing tool builds the proposed
// role and hands it to changeRole, which decides the tier from the difference.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Deikus-LXXVII/rubi/sdk/rubiplugin"
)

var (
	roleIDRE    = regexp.MustCompile(`^r_[a-z0-9]{8}$`)
	roleNameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	roleItemRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)
	roleDenyRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}(\([^\x00-\x1f\x7f]{1,200}\))?$`)
	roleToolRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	roleModelOK = []string{"inherit", "sonnet", "haiku", "opus"}
	// roleHostRE is Rubi Home's host syntax (internal/home/agent/roles/validate.go): a name with at least one dot, an
	// optional leading "*.".
	roleHostRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	labelRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// approvalText is the check for a Bot's text that the user will read in an approval (a command, a URL, a host, a rule,
// a source): valid UTF-8, one line of at most max bytes, and none of the format, control or private-use characters
// (bidi overrides and zero-width characters) that make a line read differently from what it is. It returns the
// reason, or "".
func approvalText(what, v string, max int) string {
	switch {
	case !utf8.ValidString(v):
		return what + " is not valid text"
	case len(v) > max:
		return fmt.Sprintf("%s is longer than %d bytes", what, max)
	case hiddenChars(v):
		return what + " has a hidden or control character (format, bidi or zero-width); use plain text"
	}
	return ""
}

// checkHost says whether h is a host name the way Rubi Home takes it (a leading "*." allowed).
func checkHost(h string) string {
	if r := approvalText("host", h, 253); r != "" {
		return r
	}
	if !roleHostRE.MatchString(h) {
		return "host " + clipOne(h, 64) + " is not a host name such as cdn.example.com (letters, digits, dots and hyphens, at least one dot)"
	}
	return ""
}

// checkMCP checks one MCP server the way Home will, before anyone is asked. A URL must be https without
// credentials and with a real host; a command is a plain program name or path with plain args.
func checkMCP(e roleMCP) []string {
	var out []string
	add := func(r string) {
		if r != "" {
			out = append(out, "MCP server "+clipOne(e.Name, 32)+": "+r)
		}
	}
	for _, r := range []string{approvalText("name", e.Name, 64), approvalText("type", e.Type, 16), approvalText("url", e.URL, 500), approvalText("command", e.Command, 200)} {
		add(r)
	}
	for _, a := range e.Args {
		add(approvalText("an arg", a, 200))
	}
	if len(out) > 0 {
		return out
	}
	if !roleNameRE.MatchString(e.Name) {
		add("the name must be 1 to 32 characters of a-z, 0-9 and -")
	}
	switch e.Type {
	case "http", "sse":
		u, err := url.Parse(e.URL)
		switch {
		case err != nil || u.Scheme != "https" || u.Host == "":
			add("an https URL is needed")
		case u.User != nil:
			add("the URL must not carry a user name or password")
		case !hostnameOK(u.Hostname()):
			add("the URL's host is not a valid host name")
		}
		if e.Command != "" || len(e.Args) > 0 {
			add("a url server has no command or args")
		}
	case "stdio":
		if e.Command == "" || e.URL != "" {
			add("a command is needed (and no url)")
		}
		if len(e.Args) > 16 {
			add("at most 16 args")
		}
	default:
		add("type must be http, sse or stdio")
	}
	return out
}

func hostnameOK(h string) bool {
	h = strings.ToLower(h)
	return len(h) > 0 && len(h) <= 253 && (net.ParseIP(h) != nil || labelRE.MatchString(h))
}

// checkPlugin checks a Claude plugin: a plain name, and a source of one word (a marketplace name, owner/repo or an
// https URL without credentials).
func checkPlugin(e rolePlugin) []string {
	var out []string
	add := func(r string) {
		if r != "" {
			out = append(out, "plugin "+clipOne(e.Name, 32)+": "+r)
		}
	}
	add(approvalText("name", e.Name, 64))
	add(approvalText("source", e.Source, 200))
	if len(out) > 0 {
		return out
	}
	if !roleNameRE.MatchString(e.Name) {
		add("the name must be 1 to 32 characters of a-z, 0-9 and -")
	}
	if e.Source == "" || strings.ContainsAny(e.Source, " \t\r\n") {
		add("a source without spaces is needed")
	} else if strings.Contains(e.Source, "://") {
		u, err := url.Parse(e.Source)
		switch {
		case err != nil || u.Scheme != "https" || u.Host == "" || !hostnameOK(u.Hostname()):
			add("a URL source must be https with a real host")
		case u.User != nil:
			add("the source URL must not carry a user name or password")
		}
	}
	return out
}

// roleToolNames lists the tools this file registers (a test checks that none changes the limits).
var roleToolNames = []string{"claude_code_role_create", "claude_code_role_update", "claude_code_role_archive", "claude_code_role_unarchive",
	"claude_code_role_skills_set", "claude_code_role_skills_add", "claude_code_role_skills_remove", "claude_code_role_tools_set",
	"claude_code_role_agents_set", "claude_code_role_mcp_set", "claude_code_role_plugins_set", "claude_code_role_hosts_set",
	"claude_code_role_ssh_grant", "claude_code_role_ssh_revoke", "claude_code_role_start", "claude_code_role_list", "claude_code_role_get",
	"claude_code_role_history"}

// roleWho is the part every role tool's input shares: who is asking, and on which computer.
type roleWho struct {
	Agent         string `json:"rubi_agent" jsonschema:"your Bot name as connected to Rubi"`
	AgentCode     string `json:"rubi_agent_code,omitempty" jsonschema:"the agent_code of your latest Rubi webhook (or call rubi_verify with your name to get one); proves you are that Bot"`
	VerifiedAgent string `json:"rubi_verified_agent,omitempty" jsonschema:"set by Rubi; don't pass it"`
	Device        string `json:"device,omitempty" jsonschema:"the computer, when there are several"`
}

type roleCreateIn struct {
	roleWho
	Project     string `json:"project" jsonschema:"the project (id or directory, as claude_code_projects/claude_code_sessions show it) the role is for"`
	Name        string `json:"name" jsonschema:"1 to 32 characters of a-z, 0-9 and -, unique on the project; not 'default'"`
	Description string `json:"description,omitempty" jsonschema:"what the role is for (at most 300 characters)"`
	FromRole    string `json:"from_role,omitempty" jsonschema:"a role id of the same project whose instructions, tools, deny rules, subagents and mode are copied (not its skills, MCP servers, plugins, hosts or SSH grants)"`
}

type roleUpdateIn struct {
	roleWho
	Role                string  `json:"role" jsonschema:"the role id (r_...) from claude_code_role_list"`
	Name                *string `json:"name,omitempty"`
	Description         *string `json:"description,omitempty"`
	Instructions        *string `json:"instructions,omitempty" jsonschema:"the role's prompt, appended to the system prompt (at most 8 KiB)"`
	ProjectInstructions *bool   `json:"project_instructions,omitempty" jsonschema:"append the project's CLAUDE.md"`
	DefaultMode         *string `json:"default_mode,omitempty" jsonschema:"plan, default, acceptEdits, auto or bypassPermissions; above the user's ceiling it asks the user"`
	RevertTo            int     `json:"revert_to,omitempty" jsonschema:"make a new version with the content of this older version (alone, without the other fields)"`
}

type roleRefIn struct {
	roleWho
	Role string `json:"role" jsonschema:"the role id (r_...) from claude_code_role_list"`
}

type roleSkillIn struct {
	Name        string `json:"name" jsonschema:"1 to 48 characters of a-z, 0-9 and -"`
	Description string `json:"description,omitempty" jsonschema:"one line saying when to use the skill (at most 300 characters); needed unless content is a whole SKILL.md with its own frontmatter"`
	Content     string `json:"content" jsonschema:"the skill's text (at most 32 KiB). It is only context for Claude: frontmatter keys other than name and description are stripped, and it grants nothing"`
}

type roleSkillsSetIn struct {
	roleWho
	Role   string        `json:"role"`
	Skills []roleSkillIn `json:"skills" jsonschema:"the complete list of your ad-hoc skills for the role; ones left out are removed"`
}

type roleSkillsAddIn struct {
	roleWho
	Role        string `json:"role"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Content     string `json:"content,omitempty"`
	Library     string `json:"library,omitempty" jsonschema:"a shared library skill: id follows the latest admitted version, id@3 pins version 3; instead of name, description and content. Only admitted skills can be attached"`
}

type roleSkillsRemoveIn struct {
	roleWho
	Role string `json:"role"`
	Name string `json:"name"`
}

type roleToolsSetIn struct {
	roleWho
	Role  string    `json:"role"`
	Tools *[]string `json:"tools,omitempty" jsonschema:"the built-in tools the role has; leave out to keep them. Read, Edit, Write, Glob, Grep, Bash, Agent, Skill, WebFetch and WebSearch are yours to give; any other (Cron*, Workflow, Monitor, SendMessage ...) asks the user"`
	Deny  *[]string `json:"deny,omitempty" jsonschema:"deny rules such as Bash(git push:*); the complete list, leave out to keep it. Removing a rule the user set asks the user"`
}

type roleAgentIn struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt"`
	Tools       []string `json:"tools,omitempty" jsonschema:"cut to the role's tools"`
	Model       string   `json:"model,omitempty" jsonschema:"inherit (default), sonnet, haiku or opus"`
}

type roleAgentsSetIn struct {
	roleWho
	Role   string        `json:"role"`
	Agents []roleAgentIn `json:"agents" jsonschema:"the complete list of subagent definitions"`
}

type roleMCPIn struct {
	Name    string   `json:"name"`
	Type    string   `json:"type" jsonschema:"http, sse or stdio"`
	URL     string   `json:"url,omitempty"`
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type roleMCPSetIn struct {
	roleWho
	Role string      `json:"role"`
	MCP  []roleMCPIn `json:"mcp" jsonschema:"the complete list of MCP servers; always asks the user"`
}

type rolePluginIn struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type rolePluginsSetIn struct {
	roleWho
	Role    string         `json:"role"`
	Plugins []rolePluginIn `json:"plugins" jsonschema:"the complete list of Claude plugins; always asks the user"`
}

type roleHostsSetIn struct {
	roleWho
	Role  string   `json:"role"`
	Hosts []string `json:"hosts" jsonschema:"the complete list of extra network hosts for this role; always asks the user"`
}

type roleSSHIn struct {
	roleWho
	Role   string `json:"role"`
	Target string `json:"target" jsonschema:"the name of a registered SSH target"`
}

type roleStartIn struct {
	roleWho
	Role   string `json:"role"`
	Prompt string `json:"prompt" jsonschema:"the first message of the new session (at most 2000 characters)"`
	Name   string `json:"name,omitempty" jsonschema:"a name for the session (as claude_code_rename)"`
}

type roleListIn struct {
	roleWho
	Project string `json:"project,omitempty" jsonschema:"only this project (id or directory)"`
}

type roleGetIn struct {
	roleWho
	Role    string `json:"role"`
	Version int    `json:"version,omitempty" jsonschema:"an older version (default: the current one)"`
}

type roleHistoryIn struct {
	roleWho
	Role  string `json:"role"`
	Limit int    `json:"limit,omitempty"`
}

// registerRoleTools adds the claude_code_role_* tools.
func registerRoleTools(p *rubiplugin.Plugin, s *sisters) {
	const roleTierNote = " Changes you may make yourself are applied at once and audited (every change is a new version, revertible); a change that widens the role, or any change on a project you hold no trust for, returns status needs_approval with a link for the user, and nothing is applied until they approve."
	rubiplugin.AddTool(p, "claude_code_role_create", "Create an agent role: a named profile on a project (its own skills, subagents, tools, mode) that runs in its own VM, isolated from the repository's own .claude. Needs a project you hold a trust for; otherwise one strong approval."+roleTierNote,
		func(ctx context.Context, h *rubiplugin.Host, in roleCreateIn) (any, error) {
			return s.roleCreateTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_update", "Change a role's name, description, instructions, project_instructions or default_mode, or revert it to an older version (revert_to). A mode above the user's ceiling asks the user."+roleTierNote,
		func(ctx context.Context, h *rubiplugin.Host, in roleUpdateIn) (any, error) {
			return s.roleUpdateTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_archive", "Archive a role (it stops being offered; its history stays).",
		func(ctx context.Context, h *rubiplugin.Host, in roleRefIn) (any, error) {
			return s.roleArchiveTool(ctx, h, in, true)
		})
	rubiplugin.AddTool(p, "claude_code_role_unarchive", "Bring an archived role back.",
		func(ctx context.Context, h *rubiplugin.Host, in roleRefIn) (any, error) {
			return s.roleArchiveTool(ctx, h, in, false)
		})
	rubiplugin.AddTool(p, "claude_code_role_skills_set", "Set a role's ad-hoc skills (text only: Claude reads them as context; they grant nothing). A skill the scan flags is saved but held until the user accepts it. Library skills are added with claude_code_role_skills_add."+roleTierNote,
		func(ctx context.Context, h *rubiplugin.Host, in roleSkillsSetIn) (any, error) {
			return s.roleSkillsSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_skills_add", "Add or replace one ad-hoc skill of a role (name, description, content), or attach a shared library skill (library: id follows the latest admitted version, id@3 pins version 3; only admitted skills, signed by Rubi). A followed skill is updated by Rubi when a newer version is admitted, and dropped if withdrawn. To share a skill you wrote, submit it to the library with rubi_library_submit."+roleTierNote,
		func(ctx context.Context, h *rubiplugin.Host, in roleSkillsAddIn) (any, error) {
			return s.roleSkillsAddTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_skills_remove", "Remove a skill from a role.",
		func(ctx context.Context, h *rubiplugin.Host, in roleSkillsRemoveIn) (any, error) {
			return s.roleSkillsRemoveTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_tools_set", "Set a role's built-in tools and deny rules. Tools of the safe set (Read, Edit, Write, Glob, Grep, Bash, Agent, Skill, WebFetch, WebSearch) and added deny rules are yours; any other tool, or removing a deny rule the user set, asks the user."+roleTierNote,
		func(ctx context.Context, h *rubiplugin.Host, in roleToolsSetIn) (any, error) {
			return s.roleToolsSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_agents_set", "Set a role's subagent definitions (a subagent can never have more tools than the role).",
		func(ctx context.Context, h *rubiplugin.Host, in roleAgentsSetIn) (any, error) {
			return s.roleAgentsSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_mcp_set", "Set a role's MCP servers. Always needs the user's strong approval.",
		func(ctx context.Context, h *rubiplugin.Host, in roleMCPSetIn) (any, error) {
			return s.roleMCPSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_plugins_set", "Set a role's Claude plugins (they run code). Always needs the user's strong approval.",
		func(ctx context.Context, h *rubiplugin.Host, in rolePluginsSetIn) (any, error) {
			return s.rolePluginsSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_hosts_set", "Set the extra network hosts a role may reach. Always needs the user's strong approval.",
		func(ctx context.Context, h *rubiplugin.Host, in roleHostsSetIn) (any, error) {
			return s.roleHostsSetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_ssh_grant", "Grant a role one registered SSH target (the user registers targets on Rubi's panel; an unregistered name is rejected). Applied at once and audited; the role can then run the target's allowed commands over SSH from its VM.",
		func(ctx context.Context, h *rubiplugin.Host, in roleSSHIn) (any, error) {
			return s.roleSSHTool(ctx, h, in, true)
		})
	rubiplugin.AddTool(p, "claude_code_role_ssh_revoke", "Revoke a role's SSH target. Applied at once; streams the role has open to it are cut.",
		func(ctx context.Context, h *rubiplugin.Host, in roleSSHIn) (any, error) {
			return s.roleSSHTool(ctx, h, in, false)
		})
	rubiplugin.AddTool(p, "claude_code_role_start", "Start a session in a role's own VM with your prompt as its first message and bind yourself to it. Like claude_code_start: one strong approval, or none inside a project the user trusts for you (never for a role whose mode is bypassPermissions).",
		func(ctx context.Context, h *rubiplugin.Host, in roleStartIn) (any, error) {
			return s.roleStartTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_list", "List the agent roles on the user's computer(s): id, project, name, status, version, who changed it, and the projects' default roles.",
		func(ctx context.Context, h *rubiplugin.Host, in roleListIn) (any, error) {
			return s.roleListTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_get", "Read a role (a version of it): instructions, skills with their scan results (not their text), subagents, tools, deny rules, MCP servers, plugins, hosts, SSH grants and mode.",
		func(ctx context.Context, h *rubiplugin.Host, in roleGetIn) (any, error) {
			return s.roleGetTool(ctx, h, in)
		})
	rubiplugin.AddTool(p, "claude_code_role_history", "List a role's versions, newest first: who changed what, the tier and the approval.",
		func(ctx context.Context, h *rubiplugin.Host, in roleHistoryIn) (any, error) {
			return s.roleHistoryTool(ctx, h, in)
		})
}

// ---- common steps ----

type roleCaller struct {
	Bot string
	Dev rubiplugin.HomeDevice
	Lim roleLimits
}

const notVerified = "Rubi didn't confirm which Bot you are: pass rubi_agent (your Bot name) and rubi_agent_code (the agent_code of your latest Rubi webhook, or call rubi_verify to get one); roles are changed in the name of the Bot Rubi confirms"

// who takes the Bot from Rubi's verification only. rubi_agent, as typed, is never used.
func (s *sisters) who(h sisterHost, w roleWho) (roleCaller, error) {
	bot := strings.TrimSpace(w.VerifiedAgent)
	if bot == "" || len(bot) > 64 || botID(bot) == "" {
		return roleCaller{}, errors.New(notVerified)
	}
	if botID(bot) == panelUser || botID(bot) == libraryActor {
		return roleCaller{}, errors.New("that Bot name is reserved for the user's own changes on the panel and the skill library's updates; connect under another name")
	}
	d, err := s.pickDevice(h, w.Device)
	if err != nil {
		return roleCaller{}, err
	}
	return roleCaller{Bot: bot, Dev: d, Lim: roleLimitsOf(h)}, nil
}

// roleFor reads the current version of a stored role. The project's default role (its id is the project's) is not
// a stored role and a Bot can't change it.
func (s *sisters) roleFor(ctx context.Context, h sisterHost, c roleCaller, ref string) (*role, error) {
	ref = strings.TrimSpace(ref)
	if !roleIDRE.MatchString(ref) {
		return nil, errors.New("role must be a role id such as r_ab12cd34 (claude_code_role_list shows them); a project's default role can't be changed by a Bot, create a role instead")
	}
	return s.getRole(ctx, h, c.Dev.ID, ref, 0)
}

func (s *sisters) projectOf(ctx context.Context, h sisterHost, c roleCaller, ref string) (agentProject, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > 1024 {
		return agentProject{}, errors.New("project is empty or too long")
	}
	projects, err := s.agentProjects(ctx, h, c.Dev.ID)
	if err != nil {
		return agentProject{}, err
	}
	proj, ok := matchProject(projects, ref)
	if !ok {
		var names []string
		for _, p := range projects {
			names = append(names, p.ID+" ("+p.Dir+")")
		}
		return agentProject{}, fmt.Errorf("no such project on %s: pass project (one of: %s)", c.Dev.Name, strings.Join(names, ", "))
	}
	return proj, nil
}

// update runs one change of an existing role: edit builds the proposed role from a copy of the current one.
func (s *sisters) roleEdit(ctx context.Context, h sisterHost, w roleWho, ref, op string, forceWiden bool, edit func(c roleCaller, cur, next *role) (map[string]string, []string, error)) (any, error) {
	c, err := s.who(h, w)
	if err != nil {
		return nil, err
	}
	cur, err := s.roleFor(ctx, h, c, ref)
	if err != nil {
		return nil, err
	}
	next := cur.clone()
	blobs, reasons, err := edit(c, cur, next)
	if err != nil {
		return nil, err
	}
	if len(reasons) > 0 {
		return rejected(reasons...), nil
	}
	return s.changeRole(ctx, h, roleChangeReq{Bot: c.Bot, Dev: c.Dev, Op: op, Cur: cur, Next: next, Blobs: blobs, Lim: c.Lim, ForceWiden: forceWiden})
}

func checkText(what, v string, max int) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("%s is not valid text", what)
	}
	if len(v) > max {
		return fmt.Errorf("%s is longer than %d bytes", what, max)
	}
	return nil
}

// ---- create, update, archive ----

func (s *sisters) roleCreateTool(ctx context.Context, h sisterHost, in roleCreateIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(in.Name)
	if !roleNameRE.MatchString(name) || name == "default" {
		return nil, errors.New("name must be 1 to 32 characters of a-z, 0-9 and -, and not 'default'")
	}
	if err := checkText("description", in.Description, 300); err != nil {
		return nil, err
	}
	proj, err := s.projectOf(ctx, h, c, in.Project)
	if err != nil {
		return nil, err
	}
	next := &role{Project: proj.ID, Name: name, Description: strings.TrimSpace(in.Description), Status: "active", ProjectInstructions: true,
		Tools: slices.Clone(defaultRoleTools), DefaultMode: "default", CreatedBy: botID(c.Bot)}
	if from := strings.TrimSpace(in.FromRole); from != "" {
		src, err := s.roleFor(ctx, h, c, from)
		if err != nil {
			return nil, err
		}
		if src.Project != proj.ID {
			return rejected("from_role is a role of another project; copy from a role of " + proj.ID), nil
		}
		next.Instructions, next.ProjectInstructions = src.Instructions, src.ProjectInstructions
		next.Agents, next.Tools, next.Deny, next.DefaultMode = src.Agents, slices.Clone(src.Tools), src.Deny, src.DefaultMode
		if next.Description == "" {
			next.Description = src.Description
		}
	}
	return s.changeRole(ctx, h, roleChangeReq{Bot: c.Bot, Dev: c.Dev, Op: "role.create", Next: next, Lim: c.Lim})
}

func (s *sisters) roleUpdateTool(ctx context.Context, h sisterHost, in roleUpdateIn) (any, error) {
	return s.roleEditRevert(ctx, h, in)
}

func (s *sisters) roleEditRevert(ctx context.Context, h sisterHost, in roleUpdateIn) (any, error) {
	if in.RevertTo != 0 {
		if in.Name != nil || in.Description != nil || in.Instructions != nil || in.ProjectInstructions != nil || in.DefaultMode != nil {
			return nil, errors.New("revert_to goes alone: pass it without the other fields")
		}
		return s.roleRevert(ctx, h, in)
	}
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.update", false, func(c roleCaller, _, next *role) (map[string]string, []string, error) {
		if in.Name != nil {
			n := strings.TrimSpace(*in.Name)
			if !roleNameRE.MatchString(n) || n == "default" {
				return nil, []string{"name must be 1 to 32 characters of a-z, 0-9 and -, and not 'default'"}, nil
			}
			next.Name = n
		}
		if in.Description != nil {
			if err := checkText("description", *in.Description, 300); err != nil {
				return nil, nil, err
			}
			next.Description = strings.TrimSpace(*in.Description)
		}
		if in.Instructions != nil {
			if err := checkText("instructions", *in.Instructions, 8<<10); err != nil {
				return nil, nil, err
			}
			next.Instructions = *in.Instructions
		}
		if in.ProjectInstructions != nil {
			next.ProjectInstructions = *in.ProjectInstructions
		}
		if in.DefaultMode != nil {
			next.DefaultMode = strings.TrimSpace(*in.DefaultMode)
		}
		return nil, nil, nil
	})
}

// roleRevert makes a new version with an older version's content. It is the Bot's own to do when every version
// after the older one is a tier 1 change by this Bot; otherwise it asks the user. A revert that widens the role
// asks either way (the diff decides).
func (s *sisters) roleRevert(ctx context.Context, h sisterHost, in roleUpdateIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	cur, err := s.roleFor(ctx, h, c, in.Role)
	if err != nil {
		return nil, err
	}
	if in.RevertTo < 1 || in.RevertTo >= cur.Version {
		return rejected(fmt.Sprintf("revert_to must be an older version than the current one (%d)", cur.Version)), nil
	}
	old, err := s.getRole(ctx, h, c.Dev.ID, cur.ID, in.RevertTo)
	if err != nil {
		return nil, err
	}
	var hist struct {
		Versions []struct {
			Version   int             `json:"version"`
			ChangedBy string          `json:"changed_by"`
			Change    *roleChangeInfo `json:"change"`
		} `json:"versions"`
	}
	hctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	others := false
	if err := h.HomeCall(hctx, c.Dev.ID, opRoleHistory, map[string]any{"id": cur.ID, "limit": 100}, &hist); err != nil {
		others = true
	}
	seen := 0
	for _, v := range hist.Versions {
		if v.Version <= in.RevertTo {
			continue
		}
		seen++
		if v.ChangedBy != botID(c.Bot) || v.Change == nil || v.Change.Tier != 1 {
			others = true
		}
	}
	if seen != cur.Version-in.RevertTo {
		others = true
	}
	next := old.clone()
	next.ID, next.Version, next.Parent, next.Project = cur.ID, cur.Version, cur.Version, cur.Project
	next.CreatedBy, next.CreatedAt = cur.CreatedBy, cur.CreatedAt
	clearStaleApprovals(cur, next)
	return s.changeRole(ctx, h, roleChangeReq{Bot: c.Bot, Dev: c.Dev, Op: fmt.Sprintf("role.revert(%d)", in.RevertTo), Cur: cur, Next: next, Lim: c.Lim, RevertOthers: others})
}

// clearStaleApprovals prepares a version taken from the past: an MCP server or plugin that the current version
// doesn't have in the same form keeps no approval id (the old one was spent by the version that added it), so
// the approval that allows the revert gives it a fresh one. One the current version has keeps its own.
func clearStaleApprovals(cur, next *role) {
	for i, m := range next.MCP {
		if j := slices.IndexFunc(cur.MCP, func(o roleMCP) bool { return sameMCP(o, m) }); j >= 0 {
			next.MCP[i].Approval = cur.MCP[j].Approval
		} else {
			next.MCP[i].Approval = ""
		}
	}
	for i, p := range next.Plugins {
		if j := slices.IndexFunc(cur.Plugins, func(o rolePlugin) bool { return o.Name == p.Name && o.Source == p.Source }); j >= 0 {
			next.Plugins[i].Approval = cur.Plugins[j].Approval
		} else {
			next.Plugins[i].Approval = ""
		}
	}
}

func (s *sisters) roleArchiveTool(ctx context.Context, h sisterHost, in roleRefIn, archive bool) (any, error) {
	op, st := "role.archive", "archived"
	if !archive {
		op, st = "role.unarchive", "active"
	}
	return s.roleEdit(ctx, h, in.roleWho, in.Role, op, false, func(_ roleCaller, _, next *role) (map[string]string, []string, error) {
		next.Status = st
		return nil, nil, nil
	})
}

// ---- skills ----

// skillText makes the SKILL.md text of a skill: the content as given when it carries its own frontmatter, else
// the content under a name and description.
func skillText(in roleSkillIn) (string, []string) {
	name := strings.TrimSpace(in.Name)
	if !roleItemRE.MatchString(name) {
		return "", []string{"skill name must be 1 to 48 characters of a-z, 0-9 and -"}
	}
	if !utf8.ValidString(in.Content) || !utf8.ValidString(in.Description) {
		return "", []string{"skill " + name + " is not valid text"}
	}
	text := in.Content
	if !strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "---") {
		d := strings.TrimSpace(in.Description)
		if d == "" || len(d) > 300 || strings.ContainsAny(d, "\r\n") {
			return "", []string{"skill " + name + ": give a one-line description of at most 300 characters (or content with its own frontmatter)"}
		}
		text = "---\nname: " + name + "\ndescription: " + d + "\n---\n" + in.Content
	}
	if len(text) > maxSkillBytes {
		return "", []string{fmt.Sprintf("skill %s is over %d KiB", name, maxSkillBytes>>10)}
	}
	return text, nil
}

func shaOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// applySkills puts skills (ad-hoc, by name) into next: a skill whose text is unchanged keeps its entry (and what
// the user accepted), a new or changed one is a new entry with its text in blobs. With replaceAll the ad-hoc skills
// not listed are dropped; library skills always stay.
func applySkills(c roleCaller, cur, next *role, in []roleSkillIn, replaceAll bool) (map[string]string, []string) {
	blobs := map[string]string{}
	byName := map[string]roleSkill{}
	for _, k := range cur.Skills {
		byName[k.Name] = k
	}
	var reasons []string
	listed := map[string]bool{}
	var out []roleSkill
	for _, k := range cur.Skills {
		if k.Source != "adhoc" || !replaceAll {
			out = append(out, k)
		}
	}
	for _, sk := range in {
		name := strings.TrimSpace(sk.Name)
		sk.Name = name
		if listed[name] {
			reasons = append(reasons, "skill "+clipOne(name, 48)+" is listed twice")
			continue
		}
		listed[name] = true
		text, r := skillText(sk)
		if len(r) > 0 {
			reasons = append(reasons, r...)
			continue
		}
		old, exists := byName[name]
		if exists && old.Source != "adhoc" {
			reasons = append(reasons, "skill "+name+" is a library skill of the role; remove it first")
			continue
		}
		sha := shaOf(text)
		entry := roleSkill{Name: name, Source: "adhoc", SHA256: sha, AddedBy: botID(c.Bot)}
		if exists && old.SHA256 == sha {
			entry = old
		} else {
			blobs[sha] = text
		}
		replaced := false
		for i := range out {
			if out[i].Name == name {
				out[i], replaced = entry, true
			}
		}
		if !replaced {
			out = append(out, entry)
		}
	}
	next.Skills = out
	return blobs, reasons
}

func (s *sisters) roleSkillsSetTool(ctx context.Context, h sisterHost, in roleSkillsSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.skills.set", false, func(c roleCaller, cur, next *role) (map[string]string, []string, error) {
		b, r := applySkills(c, cur, next, in.Skills, true)
		return b, r, nil
	})
}

func (s *sisters) roleSkillsAddTool(ctx context.Context, h sisterHost, in roleSkillsAddIn) (any, error) {
	if strings.TrimSpace(in.Library) != "" {
		return s.roleSkillsAddLibrary(ctx, h, in)
	}
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.skills.add", false, func(c roleCaller, cur, next *role) (map[string]string, []string, error) {
		b, r := applySkills(c, cur, next, []roleSkillIn{{Name: in.Name, Description: in.Description, Content: in.Content}}, false)
		return b, r, nil
	})
}

func (s *sisters) roleSkillsRemoveTool(ctx context.Context, h sisterHost, in roleSkillsRemoveIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.skills.remove", false, func(_ roleCaller, cur, next *role) (map[string]string, []string, error) {
		name := strings.TrimSpace(in.Name)
		next.Skills = slices.DeleteFunc(slices.Clone(cur.Skills), func(k roleSkill) bool { return k.Name == name })
		if len(next.Skills) == len(cur.Skills) {
			return nil, []string{"the role has no skill " + clipOne(name, 48)}, nil
		}
		return nil, nil, nil
	})
}

// ---- tools, subagents, MCP, plugins, hosts, SSH ----

func (s *sisters) roleToolsSetTool(ctx context.Context, h sisterHost, in roleToolsSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.tools.set", false, func(c roleCaller, cur, next *role) (map[string]string, []string, error) {
		var reasons []string
		if in.Tools != nil {
			var tools []string
			for _, t := range *in.Tools {
				t = strings.TrimSpace(t)
				switch {
				case !roleToolRE.MatchString(t) || !slices.Contains(knownRoleTools, t):
					reasons = append(reasons, "unknown tool "+clipOne(t, 40)+" (known: "+strings.Join(knownRoleTools, ", ")+")")
				case !slices.Contains(tools, t):
					tools = append(tools, t)
				}
			}
			next.Tools = tools
		}
		if in.Deny != nil {
			var deny []roleDeny
			for _, rule := range *in.Deny {
				rule = strings.TrimSpace(rule)
				if !roleDenyRE.MatchString(rule) || hiddenChars(rule) {
					reasons = append(reasons, "bad deny rule "+clipOne(rule, 60)+" (Tool or Tool(pattern), for example Bash(git push:*))")
					continue
				}
				if slices.ContainsFunc(deny, func(d roleDeny) bool { return d.Rule == rule }) {
					continue
				}
				d := roleDeny{Rule: rule, By: botID(c.Bot)}
				if i := slices.IndexFunc(cur.Deny, func(x roleDeny) bool { return x.Rule == rule }); i >= 0 {
					d = cur.Deny[i]
				}
				deny = append(deny, d)
			}
			next.Deny = deny
		}
		return nil, reasons, nil
	})
}

func (s *sisters) roleAgentsSetTool(ctx context.Context, h sisterHost, in roleAgentsSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.agents.set", false, func(_ roleCaller, _, next *role) (map[string]string, []string, error) {
		var reasons []string
		var agents []roleAgent
		for _, a := range in.Agents {
			a.Name = strings.TrimSpace(a.Name)
			if !roleItemRE.MatchString(a.Name) {
				reasons = append(reasons, "subagent name "+clipOne(a.Name, 48)+" must be 1 to 48 characters of a-z, 0-9 and -")
			}
			if a.Model == "" {
				a.Model = "inherit"
			}
			if !slices.Contains(roleModelOK, a.Model) {
				reasons = append(reasons, "subagent "+clipOne(a.Name, 48)+": model must be one of "+strings.Join(roleModelOK, ", "))
			}
			if err := checkText("subagent prompt", a.Prompt, 16<<10); err != nil {
				reasons = append(reasons, err.Error())
			}
			agents = append(agents, roleAgent{Name: a.Name, Description: a.Description, Prompt: a.Prompt, Tools: nz(a.Tools), Model: a.Model})
		}
		next.Agents = agents
		return nil, reasons, nil
	})
}

func (s *sisters) roleMCPSetTool(ctx context.Context, h sisterHost, in roleMCPSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.mcp.set", true, func(_ roleCaller, cur, next *role) (map[string]string, []string, error) {
		var reasons []string
		var list []roleMCP
		for _, m := range in.MCP {
			e := roleMCP{Name: strings.TrimSpace(m.Name), Type: strings.TrimSpace(m.Type), URL: strings.TrimSpace(m.URL), Command: strings.TrimSpace(m.Command), Args: m.Args}
			reasons = append(reasons, checkMCP(e)...)
			if slices.ContainsFunc(list, func(o roleMCP) bool { return o.Name == e.Name }) {
				reasons = append(reasons, "MCP server "+clipOne(e.Name, 32)+" is listed twice")
			}
			// An unchanged server keeps the approval it was allowed with.
			if i := slices.IndexFunc(cur.MCP, func(o roleMCP) bool { return sameMCP(o, e) }); i >= 0 {
				e = cur.MCP[i]
			}
			list = append(list, e)
		}
		next.MCP = list
		return nil, reasons, nil
	})
}

func (s *sisters) rolePluginsSetTool(ctx context.Context, h sisterHost, in rolePluginsSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.plugins.set", true, func(_ roleCaller, cur, next *role) (map[string]string, []string, error) {
		var reasons []string
		var list []rolePlugin
		for _, p := range in.Plugins {
			e := rolePlugin{Name: strings.TrimSpace(p.Name), Source: strings.TrimSpace(p.Source)}
			reasons = append(reasons, checkPlugin(e)...)
			if slices.ContainsFunc(list, func(o rolePlugin) bool { return o.Name == e.Name }) {
				reasons = append(reasons, "plugin "+clipOne(e.Name, 32)+" is listed twice")
			}
			if i := slices.IndexFunc(cur.Plugins, func(o rolePlugin) bool { return o.Name == e.Name && o.Source == e.Source }); i >= 0 {
				e = cur.Plugins[i]
			}
			list = append(list, e)
		}
		next.Plugins = list
		return nil, reasons, nil
	})
}

func (s *sisters) roleHostsSetTool(ctx context.Context, h sisterHost, in roleHostsSetIn) (any, error) {
	return s.roleEdit(ctx, h, in.roleWho, in.Role, "role.hosts.set", true, func(_ roleCaller, _, next *role) (map[string]string, []string, error) {
		var hosts, reasons []string
		for _, x := range in.Hosts {
			x = strings.ToLower(strings.TrimSpace(x))
			if r := checkHost(x); r != "" {
				reasons = append(reasons, r)
			} else if !slices.Contains(hosts, x) {
				hosts = append(hosts, x)
			}
		}
		next.Hosts = hosts
		return nil, reasons, nil
	})
}

func (s *sisters) roleSSHTool(ctx context.Context, h sisterHost, in roleSSHIn, grant bool) (any, error) {
	if _, err := s.who(h, in.roleWho); err != nil {
		return nil, err
	}
	op := "role.ssh.revoke"
	if grant {
		op = "role.ssh.grant"
	}
	target := strings.TrimSpace(in.Target)
	return s.roleEdit(ctx, h, in.roleWho, in.Role, op, false, func(c roleCaller, cur, next *role) (map[string]string, []string, error) {
		if !sshNameRE.MatchString(target) {
			return nil, []string{"target must be the name of an SSH target"}, nil
		}
		if grant {
			// Only a target the user registered can be granted; a Bot can't register one or ask for one to exist.
			if err := s.refreshSSH(ctx, h, c.Dev.ID); err != nil {
				return nil, nil, err
			}
			if !s.registeredSSH(c.Dev.ID)[target] {
				return nil, []string{"the SSH target " + target + " isn't registered; only the user registers targets (on Rubi's SSH targets page), so ask them"}, nil
			}
			next.SSH = append(slices.Clone(cur.SSH), target)
			slices.Sort(next.SSH)
			next.SSH = slices.Compact(next.SSH)
		} else {
			next.SSH = slices.DeleteFunc(slices.Clone(cur.SSH), func(t string) bool { return t == target })
		}
		return nil, nil, nil
	})
}

// ---- reading ----

func (s *sisters) roleListTool(ctx context.Context, h sisterHost, in roleListIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	project := ""
	if strings.TrimSpace(in.Project) != "" {
		p, err := s.projectOf(ctx, h, c, in.Project)
		if err != nil {
			return nil, err
		}
		project = p.ID
	}
	d, err := s.refreshRoles(ctx, h, c.Dev.ID, true)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	for _, r := range d.roles {
		if project != "" && r.Project != project {
			continue
		}
		rows = append(rows, map[string]any{"id": r.ID, "project": r.Project, "name": r.Name, "description": clipOne(r.Description, 200), "status": r.Status,
			"version": r.Version, "changed_by": r.ChangedBy, "created_by": r.CreatedBy, "yours": r.CreatedBy == botID(c.Bot)})
	}
	slices.SortFunc(rows, func(a, b map[string]any) int {
		return strings.Compare(fmt.Sprint(a["project"], "/", a["name"], "/", a["id"]), fmt.Sprint(b["project"], "/", b["name"], "/", b["id"]))
	})
	var legacy []string
	for p := range d.legacy {
		if project == "" || p == project {
			legacy = append(legacy, p)
		}
	}
	slices.Sort(legacy)
	return map[string]any{"computer": c.Dev.Name, "roles": rows, "default_roles_of_projects": legacy,
		"note": "A project's default role uses the repository's own .claude and can't be changed by a Bot."}, nil
}

func (s *sisters) roleGetTool(ctx context.Context, h sisterHost, in roleGetIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSpace(in.Role)
	if !roleIDRE.MatchString(ref) {
		return nil, errors.New("role must be a role id such as r_ab12cd34 (claude_code_role_list shows them)")
	}
	return s.getRole(ctx, h, c.Dev.ID, ref, in.Version)
}

func (s *sisters) roleHistoryTool(ctx context.Context, h sisterHost, in roleHistoryIn) (any, error) {
	c, err := s.who(h, in.roleWho)
	if err != nil {
		return nil, err
	}
	ref := strings.TrimSpace(in.Role)
	if !roleIDRE.MatchString(ref) {
		return nil, errors.New("role must be a role id such as r_ab12cd34 (claude_code_role_list shows them)")
	}
	var out map[string]any
	hctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	if err := h.HomeCall(hctx, c.Dev.ID, opRoleHistory, map[string]any{"id": ref, "limit": in.Limit}, &out); err != nil {
		return nil, roleHomeErr("couldn't read the history", err)
	}
	return out, nil
}
