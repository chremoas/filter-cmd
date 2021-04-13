package command

import (
	"strings"

	"github.com/chremoas/chremoas/args"
	proto "github.com/chremoas/chremoas/proto"
	pclient "github.com/chremoas/perms-srv/client"
	permsrv "github.com/chremoas/perms-srv/proto"
	rclient "github.com/chremoas/role-srv/client"
	rolesrv "github.com/chremoas/role-srv/proto"
	common "github.com/chremoas/services-common/command"
	"golang.org/x/net/context"
)

type ClientFactory interface {
	NewPermsClient() permsrv.PermissionsService
	NewRoleClient() rolesrv.RolesService
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

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
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

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	// This needs to be passed to role-srv if we continue to use microservices
	//if len(req.Args) > 3 {
	//	if req.Args[3] == "force" {
	//		role.RemoveAllMembers(ctx, req.Args[2], req.Sender)
	//	}
	//}

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

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	user := common.ExtractUserId(req.Args[2])

	return role.AddMember(ctx, req.Sender, user, req.Args[3])
}

func removeMember(ctx context.Context, req *proto.ExecRequest) string {
	if len(req.Args) < 4 {
		return common.SendError("Usage: !filter remove <user> <filter>")
	}

	canPerform, err := role.Permissions.CanPerform(ctx, req.Sender)
	if err != nil {
		return common.SendFatal(err.Error())
	}

	if !canPerform {
		return common.SendError("User doesn't have permission to this command")
	}

	user := common.ExtractUserId(req.Args[2])

	return role.RemoveMember(ctx, req.Sender, user, req.Args[3])
}

func syncMembers(ctx context.Context, req *proto.ExecRequest) string {
	return role.SyncMembers(ctx, req.Sender)
}

func NewCommand(name string, factory ClientFactory) *Command {
	clientFactory = factory
	role = rclient.Roles{
		RoleClient:  clientFactory.NewRoleClient(),
		PermsClient: clientFactory.NewPermsClient(),
		Permissions: pclient.NewPermission(clientFactory.NewPermsClient(), []string{"role_admins"}),
	}

	return &Command{name: name, factory: factory}
}
