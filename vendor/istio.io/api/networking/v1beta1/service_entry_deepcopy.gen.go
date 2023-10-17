// Code generated by protoc-gen-deepcopy. DO NOT EDIT.
package v1beta1

import (
	proto "google.golang.org/protobuf/proto"
)

// DeepCopyInto supports using ServiceEntry within kubernetes types, where deepcopy-gen is used.
func (in *ServiceEntry) DeepCopyInto(out *ServiceEntry) {
	p := proto.Clone(in).(*ServiceEntry)
	*out = *p
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServiceEntry. Required by controller-gen.
func (in *ServiceEntry) DeepCopy() *ServiceEntry {
	if in == nil {
		return nil
	}
	out := new(ServiceEntry)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInterface is an autogenerated deepcopy function, copying the receiver, creating a new ServiceEntry. Required by controller-gen.
func (in *ServiceEntry) DeepCopyInterface() interface{} {
	return in.DeepCopy()
}

// DeepCopyInto supports using ServicePort within kubernetes types, where deepcopy-gen is used.
func (in *ServicePort) DeepCopyInto(out *ServicePort) {
	p := proto.Clone(in).(*ServicePort)
	*out = *p
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServicePort. Required by controller-gen.
func (in *ServicePort) DeepCopy() *ServicePort {
	if in == nil {
		return nil
	}
	out := new(ServicePort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInterface is an autogenerated deepcopy function, copying the receiver, creating a new ServicePort. Required by controller-gen.
func (in *ServicePort) DeepCopyInterface() interface{} {
	return in.DeepCopy()
}