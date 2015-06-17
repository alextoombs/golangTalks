// Copyright 2015 Apcera Inc. All rights reserved.

// This is intended to give an interface for Kerberized servers to negotiate
// with clients using SPNEGO. A reference implementation is provided below.
package spnego

import (
	"errors"
	"net/http"

	"github.com/apcera/gssapi"
)

// Negotiate handles the SPNEGO client-server negotiation.
func (k KerberizedServer) Negotiate(cred *gssapi.CredId, inHeader, outHeader http.Header) (string, int, error) {
	negotiate, inputToken := CheckSPNEGONegotiate(k.Lib, inHeader, "Authorization")
	defer inputToken.Release()

	if !negotiate || inputToken.Length() == 0 {
		AddSPNEGONegotiate(outHeader, "WWW-Authenticate", inputToken)
		return "", http.StatusUnauthorized, errors.New("SPNEGO: unauthorized")
	}

	ctx, srcName, _, outputToken, _, _, delegatedCredHandle, err :=
		k.AcceptSecContext(k.GSS_C_NO_CONTEXT,
			cred, inputToken, k.GSS_C_NO_CHANNEL_BINDINGS)
	if err != nil {
		return "", http.StatusBadRequest, err
	}
	delegatedCredHandle.Release()
	ctx.DeleteSecContext()
	outputToken.Release()
	defer srcName.Release()

	return srcName.String(), http.StatusOK, nil
}

// fin
