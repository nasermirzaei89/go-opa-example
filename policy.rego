package authz

import rego.v1

default allow := false

allow if {
  input.method == "GET"
  input.path == "/restricted"
  input.user == "bob"
}
