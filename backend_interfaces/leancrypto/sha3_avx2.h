/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
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

#ifndef SHA3_AVX2
#define SHA3_AVX2

#ifdef __cplusplus
extern "C"
{
#endif

extern const struct lc_hash *lc_sha3_224_avx2;
extern const struct lc_hash *lc_sha3_256_avx2;
extern const struct lc_hash *lc_sha3_384_avx2;
extern const struct lc_hash *lc_sha3_512_avx2;

extern const struct lc_hash *lc_shake128_avx2;
extern const struct lc_hash *lc_shake256_avx2;
extern const struct lc_hash *lc_cshake128_avx2;
extern const struct lc_hash *lc_cshake256_avx2;

#ifdef __cplusplus
}
#endif

#endif /* SHA3_AVX2 */
