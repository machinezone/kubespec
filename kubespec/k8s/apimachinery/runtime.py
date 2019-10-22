# Code is generated: DO NOT EDIT

# Copyright 2019 Machine Zone, Inc. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

from typing import Any, Dict

from kubespec.k8s import base
from kubespec import context
from kubespec import types
from typeguard import check_type, typechecked


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
    @context.scoped
    @typechecked
    def __init__(
        self, raw: bytes = None, contentEncoding: str = "", contentType: str = ""
    ):
        super().__init__()
        self.__raw = raw if raw is not None else b""
        self.__contentEncoding = contentEncoding
        self.__contentType = contentType

    @typechecked
    def _root(self) -> Dict[str, Any]:
        v = super()._root()
        raw = self.raw()
        check_type("raw", raw, bytes)
        v["Raw"] = raw
        contentEncoding = self.contentEncoding()
        check_type("contentEncoding", contentEncoding, str)
        v["ContentEncoding"] = contentEncoding
        contentType = self.contentType()
        check_type("contentType", contentType, str)
        v["ContentType"] = contentType
        return v

    def raw(self) -> bytes:
        """
        Raw will hold the complete serialized object which couldn't be matched
        with a registered type. Most likely, nothing should be done with this
        except for passing it through the system.
        """
        return self.__raw

    def contentEncoding(self) -> str:
        """
        ContentEncoding is encoding used to encode 'Raw' data.
        Unspecified means no encoding.
        """
        return self.__contentEncoding

    def contentType(self) -> str:
        """
        ContentType  is serialization method used to serialize 'Raw'.
        Unspecified means ContentTypeJSON.
        """
        return self.__contentType
