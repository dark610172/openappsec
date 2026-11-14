#include "simple_protection.h"
#include "ips_comp.h"
#include "debug.h"
#include "helper.h"

using namespace std;

USE_DEBUG_FLAG(D_IPS);

SimpleProtection::Impl::Impl(
        const string &_sig_name,
        const string &ssm,
        const string &keyword,
        const vector<string> &_context
    )
        :
    sig_name(_sig_name),
    context(_context)
{
    string deobfuscated_keyword = IPSHelper::deobfuscateKeyword(keyword);
    if (deobfuscated_keyword != "") {
        auto compiled = Singleton::Consume<I_KeywordsRule>::by<IPSComp>()->genRule(deobfuscated_keyword);
        if (!compiled.ok()) {
            reportConfigurationError(
                "Failed to complie keywords '" + keyword + "' in signature " + sig_name + ": " + compiled.getErr()
            );
        }
        rule = compiled.unpackMove();
    }

    auto deobfuscated_ssm = IPSHelper::deobfuscateString(ssm);
    if (deobfuscated_ssm != "") {
        auto temp_pattern = PMHook::lineToPattern(deobfuscated_ssm);
        if (!temp_pattern.ok()) reportConfigurationError("Failed first tier pattern: " + temp_pattern.getErr());
        pattern = temp_pattern.unpackMove();
    }

    if (!pattern.empty()) {
        for (const auto &name : context) {
            if (name != "HTTP_RAW") continue;
            // Track SSM occurrences even when a keyword rule completes the conjunction.
            raw_pattern_matcher = make_shared<PMHook>();
            auto prepared = raw_pattern_matcher->prepare({pattern});
            if (!prepared.ok()) reportConfigurationError("Failed RAW pattern: " + prepared.getErr());
            break;
        }
    }

    if (deobfuscated_keyword == "" && deobfuscated_ssm == "") {
        reportConfigurationError("Both Simple String and Keyword are empty in a simple protection " + sig_name);
    }
}

using MatchType = IPSSignatureSubTypes::BaseSignature::MatchType;

MatchType
SimpleProtection::Impl::getMatch(const set<PMPattern> &matches) const
{
    dbgTrace(D_IPS) << "Entering signature";
    if (!pattern.empty() && matches.find(pattern) == matches.end()) return MatchType::NO_MATCH;

    dbgTrace(D_IPS) << "Checking for rule";
    auto env = Singleton::Consume<I_Environment>::by<IPSComp>();
    auto boundary = env->get<uint>(I_KeywordsRule::getNewDataOffsetTag());
    bool fresh_ssm = false;
    if (raw_pattern_matcher && boundary.ok()) {
        auto shared_matches = env->get<shared_ptr<const set<PMPattern>>>(
            IPSSignaturesPerContext::getFreshMatchesTag()
        );
        if (shared_matches.ok()) {
            fresh_ssm = (*shared_matches)->count(pattern) != 0;
        } else {
            // Direct signature evaluations may run without the shared first-tier scan.
            auto buffer = env->get<Buffer>("HTTP_RAW");
            if (!buffer.ok()) return MatchType::NO_MATCH;
            for (const auto &match : raw_pattern_matcher->scanBufWithOffset(*buffer)) {
                // PM offsets identify the last matched byte (inclusive).
                if (match.second >= *boundary) {
                    fresh_ssm = true;
                    break;
                }
            }
        }
        if (!rule) return fresh_ssm ? MatchType::MATCH : MatchType::NO_MATCH;
    }
    if (!rule) return MatchType::MATCH;

    dbgTrace(D_IPS) << "Running keywords";
    if (fresh_ssm) {
        // A new SSM occurrence can complete a rule whose keywords only match old history.
        ScopedContext scope;
        scope.registerValue(I_KeywordsRule::getReplaySuppressionTag(), false);
        return rule->isMatch() ? MatchType::MATCH : MatchType::NO_MATCH;
    }
    return rule->isMatch() ? MatchType::MATCH : MatchType::NO_MATCH;
}

set<PMPattern>
SimpleProtection::Impl::patternsInSignature() const
{
    set<PMPattern> res;
    if (!pattern.empty()) res.insert(pattern);
    return res;
}
