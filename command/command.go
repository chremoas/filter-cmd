package command

import (
	proto "github.com/chremoas/chremoas/proto"
	permsrv "github.com/chremoas/perms-srv/proto"
	rclient "github.com/chremoas/role-srv/client"
	rolesrv "github.com/chremoas/role-srv/proto"
	"github.com/chremoas/services-common/args"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
	"strings"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsClient
	NewRoleClient() rolesrv.RolesClient
}

var role rclient.Roles
var cmdName = "filter"
var clientFactory ClientFactory

type Command struct {
	//Store anything you need the Help or Exec functions to have access to here
	name    string
	factory ClientFactory
}

func (c *Command) Help(ctx context.Context, req *proto.HelpRequest, rsp *proto.HelpResponse) error {
	rsp.Usage = c.name
	rsp.Description = "Administrate Roles, Rules and Filters"
	return nil
}

func (c *Command) Exec(ctx context.Context, req *proto.ExecRequest, rsp *proto.ExecResponse) error {
	cmd := args.NewArg(cmdName)
	cmd.Add("list", &args.Command{listFilters, "List all Filters"})
	cmd.Add("create", &args.Command{addFilter, "Add Filter"})
	cmd.Add("destroy", &args.Command{removeFilter, "Delete Filter"})
	cmd.Add("add", &args.Command{addMember, "Add Filter Member"})
	cmd.Add("remove", &args.Command{removeMember, "Remove Filter Member"})
	cmd.Add("list_members", &args.Command{listMembers, "List all Filter Members"})
	cmd.Add("sync", &args.Command{syncMembers, "Sync Filter Membership"})
	err := cmd.Exec(ctx, req, rsp)

	// I don't 100% love this, but it'll do for now. -brian
	if err != nil {
		rsp.Result = []byte(common.SendError(err.Error()))
	}
	return nil
}

func addFilter(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !filter create <filter_name> <filter_description>")
	}

	description := strings.Join(req.Args[3:], " ")

	if common.IsDiscordUser(req.Args[2]) {
		return common.SendError("Discord users may not be filters")
	}

	if common.IsDiscordUser(description) {
		return common.SendError("Discord users may not be descriptions")
	}

	return role.AddFilter(ctx, req.Sender, req.Args[2], description)
}

func listFilters(ctx context.Context, req *proto.ExecRequest) string {
	return role.ListFilters(ctx)
}

func removeFilter(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 3 {
		return common.SendError("Usage: !filter destroy <filter_name> force")
	}

	if len(req.Args) > 3 {
		if req.Args[3] == "force" {
			role.RemoveAllMembers(ctx, req.Args[2])
		}
	}

	return role.RemoveFilter(ctx, req.Sender, req.Args[2])
}

func listMembers(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) != 3 {
		return common.SendError("Usage: !filter list_members <filter_name>")
	}

	return role.ListMembers(ctx, req.Args[2])
}

func addMember(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !filter add <user> <filter>")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]

	return role.AddMember(ctx, req.Sender, user, req.Args[3])
}

func removeMember(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !filter remove <user> <filter>")
	}

	tmp := req.Args[2]
	user := tmp[2 : len(tmp)-1]

	return role.RemoveMember(ctx, req.Sender, user, req.Args[3])
}

func syncMembers(ctx context.Context, req *proto.ExecRequest) string {
	return role.SyncMembers(ctx)
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	role = rclient.Roles{
		RoleClient:  clientFactory.NewRoleClient(),
		PermsClient: clientFactory.NewPermsClient(),
		Permissions: common.Permissions{Client: clientFactory.NewPermsClient(), PermissionsList: []string{"role_admins"}},
	}

	return &Command{name: name, factory: factory}
}
