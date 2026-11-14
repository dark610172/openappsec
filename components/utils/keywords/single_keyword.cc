#include "single_keyword.h"

#include <algorithm>

using namespace std;

void
SingleKeyword::appendKeyword(unique_ptr<SingleKeyword> &&_next)
{
    if (next==nullptr) {
        next = move(_next);
    } else {
        next->appendKeyword(move(_next));
    }
}

bool
SingleKeyword::canSuppressReplay(const string &context) const
{
    return hasTrackedDependencies(context) && (next == nullptr || next->canSuppressReplay(context));
}

MatchStatus
SingleKeyword::runNext(const I_KeywordRuntimeState *curr) const
{
    auto env = Singleton::Consume<I_Environment>::by<KeywordComp>();
    auto boundary = env->get<uint>(I_KeywordsRule::getNewDataOffsetTag());
    // Only contexts with a new-data boundary (HTTP_RAW) use replay suppression; skip the other lookups.
    if (!boundary.ok()) return next == nullptr ? MatchStatus::Match : next->isMatch(curr);
    auto suppression = env->get<bool>(I_KeywordsRule::getReplaySuppressionTag());
    bool suppress_replay = !suppression.ok() || *suppression;
    if (next==nullptr) {
        if (suppress_replay && boundary.ok()) {
            auto context = env->get<string>(I_KeywordsRule::getKeywordsRuleTag());
            if (context.ok()) {
                auto end = curr->getMatchEnd(*context);
                if (end > 0 && end <= *boundary) return MatchStatus::NoMatch;
            }
        }
        return MatchStatus::Match;
    }
    auto context = env->get<string>(I_KeywordsRule::getKeywordsRuleTag());
    if (!suppression.ok() && boundary.ok() && context.ok()) {
        // Decide once for the whole rule, including terminal rejection and literal skipping.
        ScopedContext scope;
        scope.registerValue(I_KeywordsRule::getReplaySuppressionTag(), next->canSuppressReplay(*context));
        return next->isMatch(curr);
    }
    return next->isMatch(curr);
}

OffsetRuntimeState::OffsetRuntimeState(
    const I_KeywordRuntimeState *_p,
    const string &_ctx,
    uint _offset,
    uint _match_end)
        :
    prev(_p),
    ctx(_ctx),
    offset(_offset),
    match_end(_match_end)
{
}

uint
OffsetRuntimeState::getOffset(const string &requested_ctx) const
{
    if (ctx==requested_ctx) return offset;
    return prev->getOffset(requested_ctx);
}

uint
OffsetRuntimeState::getMatchEnd(const string &requested_ctx) const
{
    auto previous_end = prev->getMatchEnd(requested_ctx);
    return ctx == requested_ctx ? max(previous_end, match_end) : previous_end;
}

uint
OffsetRuntimeState::getVariable(uint requested_var_id) const
{
    return prev->getVariable(requested_var_id);
}

VariableRuntimeState::VariableRuntimeState(
    const I_KeywordRuntimeState *_p,
    uint _var_id,
    uint _val)
        :
    prev(_p),
    var_id(_var_id),
    value(_val)
{
}

uint
VariableRuntimeState::getOffset(const string &requested_ctx) const
{
    return prev->getOffset(requested_ctx);
}

uint
VariableRuntimeState::getMatchEnd(const string &requested_ctx) const
{
    return prev->getMatchEnd(requested_ctx);
}

uint
VariableRuntimeState::getVariable(uint requested_var_id) const
{
    if (var_id==requested_var_id) return value;
    return prev->getVariable(requested_var_id);
}

uint
VariablesMapping::addNewVariable(const string &param)
{
    auto iter = mapping.find(param);
    if (iter==mapping.end()) {
        mapping[param] = mapping.size();
    }
    return mapping[param];
}

Maybe<uint>
VariablesMapping::getVariableId(const string &param) const
{
    auto iter = mapping.find(param);
    if (iter==mapping.end()) {
        return genError(string("Unknown parameter ")+param);
    }
    return iter->second;
}

void
NumericAttr::setAttr(
    const KeywordAttr &attr,
    const VariablesMapping &known_vars,
    const string &keyword_name,
    const uint base,
    bool is_unsigned_val)
{
    auto &vec = attr.getParams();
    if (vec.size()!= 2) {
        throw KeywordError("Malformed " + attr.getAttrName() + "' in the '" + keyword_name + "' keyword");
    }

    setAttr(attr.getAttrName(), vec[1], known_vars, keyword_name, base, is_unsigned_val);
}

void
NumericAttr::setAttr(
    const string &attr_name,
    const string &param,
    const VariablesMapping &known_vars,
    const string &keyword_name,
    const uint base,
    bool is_unsigned_val)
{
    if (isSet()) {
        throw KeywordError("Double definition of the '" + attr_name + "' in the '" + keyword_name + "' keyword");
    }

    if (is_unsigned_val && param[0]=='-') {
        throw KeywordError(
            "Negative constant '" +
            param +
            "' in the '" +
            attr_name +
            "' in the '" +
            keyword_name +
            "' keyword"
        );
    }

    if (isdigit(param[0]) || param[0] == '-') {
        status = Status::Const;
        try {
            size_t idx;
            val = stol(param, &idx, base);
            if (idx != param.length()) throw invalid_argument("");
        }
        catch (...) {
            throw KeywordError(
                "Malformed constant '" +
                param +
                "' in the '" +
                attr_name +
                "' in the '" +
                keyword_name +
                "' keyword"
            );
        }
    } else {
        status = Status::Var;
        val = known_vars.getVariableId(param).unpack<KeywordError>(
            "In " + keyword_name +
            " in " + attr_name + ": "
        );
    }
}

int
NumericAttr::evalAttr(const I_KeywordRuntimeState *prev) const
{
    if (status==Status::Var) {
        return prev->getVariable(val);
    }
    return val;
}

void
BoolAttr::setAttr(const KeywordAttr &attr, const string &keyword_name)
{
    if (attr.getParams().size()!=1) {
        throw KeywordError("Malformed " + attr.getAttrName() + "' in the '" + keyword_name + "' keyword");
    }

    val = true;
}

void
BoolAttr::setAttr(const string &keyword_name, const string &attr_name)
{
    if (val) throw KeywordError("Double definition of the '" + attr_name + "' in the '" + keyword_name + "' keyword");

    val = true;
}

void
CtxAttr::setAttr(const KeywordAttr &attr, const string &keyword_name)
{
    if (is_set) throw KeywordError("Double definition of the 'part' in the '" + keyword_name + "' keyword");
    is_set = true;
    auto vec = attr.getParams();
    if (vec.size()!=2) throw KeywordError("Malformed 'part' in the '" + keyword_name + "' keyword");
    ctx = vec[1];
}

const map<string, ComparisonAttr::CompId> ComparisonAttr::name_to_operator {
    { "=",          CompId::EQUAL                 },
    { "!=",         CompId::NOT_EQUAL             },
    { "<",          CompId::LESS_THAN             },
    { ">",          CompId::GREATER_THAN          },
    { "<=",         CompId::LESS_THAN_OR_EQUAL    },
    { ">=",         CompId::GREATER_THAN_OR_EQUAL }
};

Maybe<ComparisonAttr::CompId>
ComparisonAttr::getComparisonByName(const string &name)
{
    auto iter = name_to_operator.find(name);
    if (iter == name_to_operator.end()) {
        return genError("Could not find the operator: " + name);
    }
    return iter->second;
}

void
ComparisonAttr::setAttr(const string &param, const string &keyword_name)
{
    if (isSet()) {
        throw KeywordError("Double definition of the comparison opearator in the '" + keyword_name + "' keyword");
    }
    is_set = true;
    comp_val = getComparisonByName(param).unpack<KeywordError>(
        "Unknown comparison operator in the '" + keyword_name  + "' keyword: "
    );
}

bool
ComparisonAttr::operator()(int first_val, int second_val) const
{
    switch (comp_val) {
        case ComparisonAttr::CompId::EQUAL: {
            return first_val == second_val;
        }
        case ComparisonAttr::CompId::NOT_EQUAL: {
            return first_val != second_val;
        }
        case ComparisonAttr::CompId::LESS_THAN: {
            return first_val < second_val;
        }
        case ComparisonAttr::CompId::GREATER_THAN: {
            return first_val > second_val;
        }
        case ComparisonAttr::CompId::LESS_THAN_OR_EQUAL: {
            return first_val <= second_val;
        }
        case ComparisonAttr::CompId::GREATER_THAN_OR_EQUAL: {
            return first_val >= second_val;
        }
    }
    dbgAssert(false)
        << AlertInfo(AlertTeam::CORE, "keywords")
        << "ComparisonAttr::operator found an invalid comparison operator";
    return false;
}

using InitFunc = unique_ptr<SingleKeyword>(*)(const vector<KeywordAttr> &, VariablesMapping &);

const map<string, InitFunc> initializers = {
    {"data",          genDataKeyword        },
    {"pcre",          genPCREKeyword        },
    {"length",        genLengthKeyword      },
    {"byte_extract",  genByteExtractKeyword },
    {"compare",       genCompareKeyword     },
    {"stateop",       genStateopKeyword     },
    {"no_match",      genNoMatchKeyword     },
    {"jump",          genJumpKeyword        }
};

unique_ptr<SingleKeyword>
getKeywordByName(const KeywordParsed &keyword, VariablesMapping &known_vars)
{
    auto iter = initializers.find(keyword.getName());
    if (iter==initializers.end()) throw KeywordError(keyword.getName() + " - unknown keyword type");
    return iter->second(keyword.getAttr(), known_vars);
}
