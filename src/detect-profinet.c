/* Copyright (C) 2015 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \Profinet Detect-Logic
 *
 * \author Ryabov Petr <agekor@yandex.ru>
 *
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-profinet.h"
#include "stream-tcp.h"

//RegEx для опций profinet
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
#define MAX_SUBSTRINGS 30
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectProfinetRegister below */
static int DetectProfinetMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectProfinetSetup (DetectEngineCtx *, Signature *, char *);
static void DetectProfinetFree (void *);
static void DetectProfinetRegisterTests (void);

/**
 * \brief Registration function for profinet: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */

void DetectProfinetRegister(void) {
    sigmatch_table[DETECT_PROFINET].name = "profinet";
    sigmatch_table[DETECT_PROFINET].Match = DetectProfinetMatch;
    sigmatch_table[DETECT_PROFINET].Setup = DetectProfinetSetup;
    sigmatch_table[DETECT_PROFINET].Free = DetectProfinetFree;
    sigmatch_table[DETECT_PROFINET].RegisterTests = DetectProfinetRegisterTests;

    /* set up the PCRE for keyword parsing */
    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at "
                "offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    if (parse_regex != NULL)
        SCFree(parse_regex);
    if (parse_regex_study != NULL)
        SCFree(parse_regex_study);
    return;
}

/**
 * \brief This function is used to match PROFINET rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectProfinetData
 *
 * \retval 0 no match
 * \retval 1 match
 */

static int DetectProfinetMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectProfinetData *profinetd = (const DetectProfinetData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
    	
        if (profinetd->arg1 == p->payload[0] &&
            profinetd->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse profinet options passed via profinet: keyword
 *
 * \param profinetstr Pointer to the user provided profinet options
 *
 * \retval profinetd pointer to DetectProfinetData on success
 * \retval NULL on failure
 */

//Парсим ключевое слово в Profinet правило
static DetectProfinetData *DetectProfinetParse (const char *profinetstr)
{
    DetectProfinetData *profinetd = NULL;
    char arg1[4] = "";
    char arg2[4] = "";
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    profinetstr, strlen(profinetstr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) profinetstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret > 2) {
        res = pcre_copy_substring((char *) profinetstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

    }
    
    /* Если получили валидную Profinet опцию */
    profinetd = SCMalloc(sizeof (DetectProfinetData));
    if (unlikely(profinetd == NULL))
        goto error;
    profinetd->arg1 = (uint8_t)atoi(arg1);
    profinetd->arg2 = (uint8_t)atoi(arg2);

    return profinetd;

error:
    if (profinetd)
        SCFree(profinetd);
    return NULL;
}

/**
 * \brief parse the options from the 'profinet' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param profinetstr pointer to the user provided profinet options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */

static int DetectProfinetSetup (DetectEngineCtx *de_ctx, Signature *s, char *profinetstr)
{
    DetectProfinetData *profinetd = NULL;
    SigMatch *sm = NULL;

    profinetd = DetectProfinetParse(profinetstr);
    if (profinetd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_PROFINET;
    sm->ctx = (void *)profinetd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (profinetd != NULL)
        DetectProfinetFree(profinetd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectProfinetData
 *
 * \param ptr pointer to DetectProfinetData
 */
static void DetectProfinetFree(void *ptr) {
    DetectProfinetData *profinetd = (DetectProfinetData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(profinetd);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectProfinetParseTest01 (void) {
    DetectProfinetData *profinetd = NULL;
    uint8_t res = 0;

    profinetd = DetectProfinetParse("1,10");
    if (profinetd != NULL) {
        if (profinetd->arg1 == 1 && profinetd->arg2 == 10)
            res = 1;

        DetectProfinetFree(profinetd);
    }

    return res;
}

static int DetectProfinetSignatureTest01 (void) {
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (profinet:1,10; sid:1; rev:1;)");
    if (sig == NULL) {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectProfinet
 */
void DetectProfinetRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectProfinetParseTest01",
            DetectProfinetParseTest01, 1);
    UtRegisterTest("DetectProfinetSignatureTest01",
            DetectProfinetSignatureTest01, 1);
#endif /* UNITTESTS */
}
