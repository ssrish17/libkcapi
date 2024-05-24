/* Kernel crypto API AF_ALG ECC Primitives API
 *
 * Copyright (C) 2022, VMware Inc.
 * Author: Alexey Makhalov <amakhalov@vmware.com>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "internal.h"
#include "kcapi.h"

DSO_PUBLIC
int kcapi_ecc_init(struct kcapi_handle **handle)
{
	int ret = _kcapi_handle_init(handle, "ecc", "ecdh", 0);
	kcapi_set_verbosity(KCAPI_LOG_DEBUG);

	if (ret)
		return ret;

	return 0;
}

DSO_PUBLIC
void kcapi_ecc_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}


DSO_PUBLIC
int32_t kcapi_ecc_verify(struct kcapi_handle *handle,
			 const uint8_t *x, uint32_t xlen,
			 const uint8_t *y, uint32_t ylen)
{
	struct iovec iov[2];

	iov[0].iov_base = (void*)(uintptr_t)x;
	iov[0].iov_len = xlen;
	iov[1].iov_base = (void*)(uintptr_t)y;
	iov[1].iov_len = ylen;

	return _kcapi_common_send_data(handle, iov, 2, 0);
}

DSO_PUBLIC
int32_t kcapi_ecc_keygen(struct kcapi_handle *handle,
			 uint8_t *privkey, uint32_t privkeylen,
			 uint8_t *x, uint32_t xlen,
			 uint8_t *y, uint32_t ylen)
{
	struct iovec iov[3];

	iov[0].iov_base = (void*)(uintptr_t)privkey;
	iov[0].iov_len = privkeylen;
	iov[1].iov_base = (void*)(uintptr_t)x;
	iov[1].iov_len = xlen;
	iov[2].iov_base = (void*)(uintptr_t)y;
	iov[2].iov_len = ylen;

	return _kcapi_common_recv_data(handle, iov, 3);
}

