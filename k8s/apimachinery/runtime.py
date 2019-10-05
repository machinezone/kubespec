# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

import addict
from k8s import base
from korps import types
from typeguard import typechecked


# RawExtension is used to hold extensions in external versions.
# 
# To use this, make a field which has RawExtension as its type in your external, versioned
# struct, and Object in your internal struct. You also need to register your
# various plugin types.
# 
# // Internal package:
# type MyAPIObject struct {
# 	runtime.TypeMeta `json:",inline"`
# 	MyPlugin runtime.Object `json:"myPlugin"`
# }
# type PluginA struct {
# 	AOption string `json:"aOption"`
# }
# 
# // External package:
# type MyAPIObject struct {
# 	runtime.TypeMeta `json:",inline"`
# 	MyPlugin runtime.RawExtension `json:"myPlugin"`
# }
# type PluginA struct {
# 	AOption string `json:"aOption"`
# }
# 
# // On the wire, the JSON will look something like this:
# {
# 	"kind":"MyAPIObject",
# 	"apiVersion":"v1",
# 	"myPlugin": {
# 		"kind":"PluginA",
# 		"aOption":"foo",
# 	},
# }
# 
# So what happens? Decode first uses json or yaml to unmarshal the serialized data into
# your external MyAPIObject. That causes the raw JSON to be stored, but not unpacked.
# The next step is to copy (using pkg/conversion) into the internal struct. The runtime
# package's DefaultScheme has conversion functions installed which will unpack the
# JSON stored in RawExtension, turning it into the correct object type, and storing it
# in the Object. (TODO: In the case where the object is of an unknown type, a
# runtime.Unknown object will be created and stored.)
class RawExtension(types.Object):
    pass  # FIXME


# Unknown allows api objects with unknown types to be passed-through. This can be used
# to deal with the API objects from a plug-in. Unknown objects still have functioning
# TypeMeta features-- kind, version, etc.
# TODO: Make this object have easy access to field based accessors and settors for
# metadata and field mutatation.
class Unknown(base.TypedObject):

    @typechecked
    def render(self) -> addict.Dict:
        v = super().render()
        v['Raw'] = self.raw()
        v['ContentEncoding'] = self.contentEncoding()
        v['ContentType'] = self.contentType()
        return v
    
    # Raw will hold the complete serialized object which couldn't be matched
    # with a registered type. Most likely, nothing should be done with this
    # except for passing it through the system.
    @typechecked
    def raw(self) -> bytes:
        return self._kwargs.get('Raw', b'')
    
    # ContentEncoding is encoding used to encode 'Raw' data.
    # Unspecified means no encoding.
    @typechecked
    def contentEncoding(self) -> str:
        return self._kwargs.get('ContentEncoding', '')
    
    # ContentType  is serialization method used to serialize 'Raw'.
    # Unspecified means ContentTypeJSON.
    @typechecked
    def contentType(self) -> str:
        return self._kwargs.get('ContentType', '')
