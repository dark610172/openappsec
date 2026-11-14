#ifndef ___I_KEYWORDS_RULE_H__
#define ___I_KEYWORDS_RULE_H__

#include <memory>
#include <string>

#include "maybe_res.h"

class I_KeywordsRule
{
public:
    class VirtualRule
    {
    public:
        virtual ~VirtualRule() {};
        virtual bool isMatch() const = 0;
    };

    virtual Maybe<std::shared_ptr<VirtualRule>> genRule(const std::string &rule) = 0;

    static const std::string & getKeywordsRuleTag() { return keywords_tag; }
    // Exclusive end offsets at or below this boundary belong entirely to old history.
    static const std::string &
    getNewDataOffsetTag()
    {
        static const std::string tag = "keywords_rule_new_data_offset";
        return tag;
    }
    // False permits overlap matches when some input dependencies are not tracked.
    static const std::string &
    getReplaySuppressionTag()
    {
        static const std::string tag = "keywords_rule_replay_suppression";
        return tag;
    }

protected:
    virtual ~I_KeywordsRule() {}

private:
    static std::string keywords_tag;
};

#endif // ___I_KEYWORDS_RULE_H__
