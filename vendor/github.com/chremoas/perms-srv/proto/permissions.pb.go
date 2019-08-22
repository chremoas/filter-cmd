// Code generated by protoc-gen-go. DO NOT EDIT.
// source: permissions.proto

/*
Package chremoas_perms is a generated protocol buffer package.

It is generated from these files:
	permissions.proto

It has these top-level messages:
	NilRequest
	UsersRequest
	UsersResponse
	PermissionsRequest
	Permission
	PermissionUser
	PermissionsResponse
	PerformResponse
*/
package chremoas_perms

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type NilRequest struct {
}

func (m *NilRequest) Reset()                    { *m = NilRequest{} }
func (m *NilRequest) String() string            { return proto.CompactTextString(m) }
func (*NilRequest) ProtoMessage()               {}
func (*NilRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type UsersRequest struct {
	Permission string `protobuf:"bytes,1,opt,name=Permission" json:"Permission,omitempty"`
}

func (m *UsersRequest) Reset()                    { *m = UsersRequest{} }
func (m *UsersRequest) String() string            { return proto.CompactTextString(m) }
func (*UsersRequest) ProtoMessage()               {}
func (*UsersRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *UsersRequest) GetPermission() string {
	if m != nil {
		return m.Permission
	}
	return ""
}

type UsersResponse struct {
	UserList []string `protobuf:"bytes,1,rep,name=UserList" json:"UserList,omitempty"`
}

func (m *UsersResponse) Reset()                    { *m = UsersResponse{} }
func (m *UsersResponse) String() string            { return proto.CompactTextString(m) }
func (*UsersResponse) ProtoMessage()               {}
func (*UsersResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *UsersResponse) GetUserList() []string {
	if m != nil {
		return m.UserList
	}
	return nil
}

type PermissionsRequest struct {
	User            string   `protobuf:"bytes,1,opt,name=User" json:"User,omitempty"`
	PermissionsList []string `protobuf:"bytes,2,rep,name=PermissionsList" json:"PermissionsList,omitempty"`
}

func (m *PermissionsRequest) Reset()                    { *m = PermissionsRequest{} }
func (m *PermissionsRequest) String() string            { return proto.CompactTextString(m) }
func (*PermissionsRequest) ProtoMessage()               {}
func (*PermissionsRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *PermissionsRequest) GetUser() string {
	if m != nil {
		return m.User
	}
	return ""
}

func (m *PermissionsRequest) GetPermissionsList() []string {
	if m != nil {
		return m.PermissionsList
	}
	return nil
}

type Permission struct {
	Name        string `protobuf:"bytes,1,opt,name=Name" json:"Name,omitempty"`
	Description string `protobuf:"bytes,2,opt,name=Description" json:"Description,omitempty"`
}

func (m *Permission) Reset()                    { *m = Permission{} }
func (m *Permission) String() string            { return proto.CompactTextString(m) }
func (*Permission) ProtoMessage()               {}
func (*Permission) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *Permission) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Permission) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

type PermissionUser struct {
	User       string `protobuf:"bytes,1,opt,name=User" json:"User,omitempty"`
	Permission string `protobuf:"bytes,2,opt,name=Permission" json:"Permission,omitempty"`
}

func (m *PermissionUser) Reset()                    { *m = PermissionUser{} }
func (m *PermissionUser) String() string            { return proto.CompactTextString(m) }
func (*PermissionUser) ProtoMessage()               {}
func (*PermissionUser) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *PermissionUser) GetUser() string {
	if m != nil {
		return m.User
	}
	return ""
}

func (m *PermissionUser) GetPermission() string {
	if m != nil {
		return m.Permission
	}
	return ""
}

type PermissionsResponse struct {
	PermissionsList []*Permission `protobuf:"bytes,1,rep,name=PermissionsList" json:"PermissionsList,omitempty"`
}

func (m *PermissionsResponse) Reset()                    { *m = PermissionsResponse{} }
func (m *PermissionsResponse) String() string            { return proto.CompactTextString(m) }
func (*PermissionsResponse) ProtoMessage()               {}
func (*PermissionsResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *PermissionsResponse) GetPermissionsList() []*Permission {
	if m != nil {
		return m.PermissionsList
	}
	return nil
}

type PerformResponse struct {
	CanPerform bool `protobuf:"varint,1,opt,name=CanPerform" json:"CanPerform,omitempty"`
}

func (m *PerformResponse) Reset()                    { *m = PerformResponse{} }
func (m *PerformResponse) String() string            { return proto.CompactTextString(m) }
func (*PerformResponse) ProtoMessage()               {}
func (*PerformResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *PerformResponse) GetCanPerform() bool {
	if m != nil {
		return m.CanPerform
	}
	return false
}

func init() {
	proto.RegisterType((*NilRequest)(nil), "chremoas.perms.NilRequest")
	proto.RegisterType((*UsersRequest)(nil), "chremoas.perms.UsersRequest")
	proto.RegisterType((*UsersResponse)(nil), "chremoas.perms.UsersResponse")
	proto.RegisterType((*PermissionsRequest)(nil), "chremoas.perms.PermissionsRequest")
	proto.RegisterType((*Permission)(nil), "chremoas.perms.Permission")
	proto.RegisterType((*PermissionUser)(nil), "chremoas.perms.PermissionUser")
	proto.RegisterType((*PermissionsResponse)(nil), "chremoas.perms.PermissionsResponse")
	proto.RegisterType((*PerformResponse)(nil), "chremoas.perms.PerformResponse")
}

func init() { proto.RegisterFile("permissions.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 385 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x94, 0x4d, 0x4f, 0xf2, 0x40,
	0x10, 0xc7, 0x81, 0xe7, 0x51, 0x61, 0x78, 0x93, 0xc1, 0x03, 0xd9, 0x28, 0x92, 0xf5, 0x42, 0x62,
	0xd2, 0x44, 0xfc, 0x04, 0x2a, 0x17, 0x13, 0x42, 0x48, 0x03, 0x89, 0x89, 0x5e, 0x10, 0xd6, 0xd8,
	0xc4, 0xb2, 0xb5, 0x53, 0xfd, 0x62, 0x7e, 0x41, 0xb3, 0x4b, 0xd9, 0x6e, 0x29, 0x2f, 0x1e, 0xb8,
	0x75, 0x67, 0x66, 0x7f, 0xf3, 0x9f, 0xff, 0x64, 0x0b, 0x8d, 0x40, 0x84, 0xbe, 0x47, 0xe4, 0xc9,
	0x05, 0x39, 0x41, 0x28, 0x23, 0x89, 0xb5, 0xd9, 0x7b, 0x28, 0x7c, 0x39, 0x25, 0x47, 0xe5, 0x88,
	0x57, 0x00, 0x86, 0xde, 0x87, 0x2b, 0x3e, 0xbf, 0x04, 0x45, 0xdc, 0x81, 0xca, 0x84, 0x44, 0x48,
	0xf1, 0x19, 0xdb, 0x00, 0x23, 0x83, 0x68, 0xe5, 0x3b, 0xf9, 0x6e, 0xc9, 0xb5, 0x22, 0xfc, 0x1a,
	0xaa, 0x71, 0x3d, 0x05, 0x72, 0x41, 0x02, 0x19, 0x14, 0x55, 0x60, 0xe0, 0x51, 0xd4, 0xca, 0x77,
	0xfe, 0x75, 0x4b, 0xae, 0x39, 0x73, 0x17, 0x30, 0xb9, 0x6a, 0x5a, 0x20, 0xfc, 0x57, 0x15, 0x31,
	0x5c, 0x7f, 0x63, 0x17, 0xea, 0x56, 0xa5, 0x86, 0x15, 0x34, 0x6c, 0x3d, 0xcc, 0xef, 0x6d, 0x81,
	0x8a, 0x35, 0x9c, 0xfa, 0x62, 0xc5, 0x52, 0xdf, 0xd8, 0x81, 0x72, 0x5f, 0xd0, 0x2c, 0xf4, 0x82,
	0x48, 0xcd, 0x50, 0xd0, 0x29, 0x3b, 0xc4, 0xfb, 0x50, 0x4b, 0x18, 0xba, 0xff, 0x26, 0x4d, 0x69,
	0x2b, 0x0a, 0x19, 0x2b, 0x9e, 0xa1, 0x99, 0x9a, 0x2e, 0x36, 0xa4, 0x9f, 0x1d, 0x45, 0xf9, 0x52,
	0xee, 0x31, 0x27, 0xbd, 0x09, 0x27, 0x29, 0xcb, 0x8e, 0x79, 0xa3, 0x29, 0x6f, 0x32, 0xf4, 0x0d,
	0xb8, 0x0d, 0xf0, 0x30, 0x5d, 0xc4, 0x51, 0xad, 0xb4, 0xe8, 0x5a, 0x91, 0xde, 0xcf, 0x11, 0x94,
	0x2d, 0x0c, 0x8e, 0xe0, 0x24, 0x4e, 0x21, 0xdf, 0xde, 0x7a, 0xb5, 0x16, 0x76, 0xb9, 0xa1, 0xc6,
	0xee, 0xcf, 0x73, 0xf8, 0x08, 0xd5, 0xbb, 0xf9, 0xdc, 0xb2, 0x7f, 0xc7, 0x48, 0x6c, 0x47, 0x8e,
	0xe7, 0x70, 0x02, 0x8d, 0x14, 0x6a, 0xe9, 0xf8, 0xf6, 0x2b, 0x2a, 0xcf, 0xf6, 0xe4, 0x79, 0x0e,
	0x07, 0x70, 0xea, 0x0a, 0x5f, 0x7e, 0x8b, 0x83, 0x88, 0x7c, 0x82, 0xb3, 0x75, 0xda, 0x81, 0x74,
	0x8e, 0xa1, 0xae, 0xd6, 0x6c, 0xaf, 0x2b, 0x23, 0x25, 0x79, 0xa5, 0xec, 0x6a, 0xe7, 0xfe, 0xcc,
	0x7e, 0xc6, 0xd0, 0x4c, 0x53, 0xf5, 0x53, 0xc5, 0xf3, 0xf5, 0xdb, 0xf6, 0x8b, 0x67, 0x17, 0x5b,
	0xb2, 0x86, 0xfa, 0xb2, 0xa4, 0xaa, 0xb0, 0xad, 0x77, 0x9f, 0x09, 0x7f, 0xd3, 0xfc, 0x7a, 0xac,
	0xff, 0x52, 0xb7, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff, 0xa4, 0xed, 0x0d, 0x1c, 0xba, 0x04, 0x00,
	0x00,
}
