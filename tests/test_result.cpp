#include <cabral/model/Result.hpp>

#include <memory>
#include <string>

#include <gtest/gtest.h>

using cabral::Failure;
using cabral::Result;

TEST(ResultType, HoldsValue) {
    Result<int, std::string> result = 42;
    ASSERT_TRUE(result.hasValue());
    EXPECT_TRUE(static_cast<bool>(result));
    EXPECT_EQ(result.value(), 42);
}

TEST(ResultType, HoldsError) {
    Result<int, std::string> result = Failure(std::string("boom"));
    ASSERT_FALSE(result.hasValue());
    EXPECT_FALSE(static_cast<bool>(result));
    EXPECT_EQ(result.error(), "boom");
}

TEST(ResultType, FactoriesMatchConstructors) {
    // Parênteses extras: a vírgula de Result<int, std::string> quebraria a macro.
    EXPECT_EQ((Result<int, std::string>::ok(7).value()), 7);
    EXPECT_EQ((Result<int, std::string>::err("bad").error()), "bad");
}

TEST(ResultType, ValueOrFallsBackOnError) {
    Result<int, std::string> ok = 5;
    Result<int, std::string> bad = Failure(std::string("e"));
    EXPECT_EQ(ok.valueOr(99), 5);
    EXPECT_EQ(bad.valueOr(99), 99);
}

TEST(ResultType, ThrowsWhenAccessingWrongAlternative) {
    Result<int, std::string> ok = 1;
    Result<int, std::string> bad = Failure(std::string("e"));
    EXPECT_THROW((void)ok.error(), std::logic_error);
    EXPECT_THROW((void)bad.value(), std::logic_error);
}

TEST(ResultType, SupportsMoveOnlyValue) {
    auto result = Result<std::unique_ptr<int>, std::string>::ok(std::make_unique<int>(3));
    ASSERT_TRUE(result.hasValue());
    auto owned = std::move(result).value();
    ASSERT_NE(owned, nullptr);
    EXPECT_EQ(*owned, 3);
}
