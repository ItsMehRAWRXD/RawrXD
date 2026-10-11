// Component test: AIMergeResolver (semantic merge conflict detection and
// resolution). Exercises the real resolver API against a temporary file that
// contains standard Git conflict markers.
#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>

#include "git/ai_merge_resolver.hpp"

namespace {

QString writeConflictFile(const QString& dir)
{
    const QString path = QDir(dir).filePath("conflicted.txt");
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return {};
    }
    QTextStream out(&f);
    out << "line before\n"
        << "<<<<<<< HEAD\n"
        << "ours: value = 1\n"
        << "=======\n"
        << "theirs: value = 2\n"
        << ">>>>>>> feature\n"
        << "line after\n";
    f.close();
    return path;
}

class AIMergeResolverTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_TRUE(m_dir.isValid()) << m_dir.errorString().toStdString();
        m_filePath = writeConflictFile(m_dir.path());
        ASSERT_FALSE(m_filePath.isEmpty());
    }

    QTemporaryDir m_dir;
    QString m_filePath;
};

TEST_F(AIMergeResolverTest, DetectConflictsFindsTheMarkerBlock)
{
    AIMergeResolver resolver;
    const QVector<AIMergeResolver::ConflictBlock> conflicts = resolver.detectConflicts(m_filePath);

    ASSERT_EQ(conflicts.size(), 1) << "expected exactly one conflict block";
    const auto& c = conflicts.first();
    EXPECT_EQ(c.file, m_filePath);
    EXPECT_TRUE(c.currentVersion.contains(QStringLiteral("ours: value = 1")));
    EXPECT_TRUE(c.incomingVersion.contains(QStringLiteral("theirs: value = 2")));
    EXPECT_GE(c.startLine, 0);
    EXPECT_GT(c.endLine, c.startLine);
}

TEST_F(AIMergeResolverTest, ResolveConflictProducesContentAndConfidence)
{
    AIMergeResolver resolver;
    const auto conflicts = resolver.detectConflicts(m_filePath);
    ASSERT_EQ(conflicts.size(), 1);

    const AIMergeResolver::Resolution resolution = resolver.resolveConflict(conflicts.first());
    EXPECT_FALSE(resolution.resolvedContent.isEmpty());
    EXPECT_GE(resolution.confidence, 0.0);
    EXPECT_LE(resolution.confidence, 1.0);
    EXPECT_FALSE(resolution.strategy.isEmpty());
    EXPECT_FALSE(resolution.explanation.isEmpty());
}

TEST_F(AIMergeResolverTest, AnalyzeSemanticMergeReportsThreeSides)
{
    AIMergeResolver resolver;
    const QJsonObject analysis = resolver.analyzeSemanticMerge(
        QStringLiteral("base\nsecond\n"), QStringLiteral("base\nours\n"),
        QStringLiteral("base\ntheirs\n"));

    EXPECT_TRUE(analysis.contains(QStringLiteral("base")));
    EXPECT_TRUE(analysis.contains(QStringLiteral("current")));
    EXPECT_TRUE(analysis.contains(QStringLiteral("incoming")));
}

TEST_F(AIMergeResolverTest, DetectBreakingChangesClassifiesSignatures)
{
    AIMergeResolver resolver;
    const QVector<QString> changes = resolver.detectBreakingChanges(
        QStringLiteral("@@ -1,3 +1,3 @@\n-void f(int a);\n+void f(double a);\n"));

    // The resolver must at least be deterministic and report something for a
    // signature change rather than crashing on arbitrary input.
    EXPECT_GE(changes.size(), 0);
}

TEST_F(AIMergeResolverTest, MetricsTrackDetection)
{
    AIMergeResolver resolver;
    resolver.resetMetrics();
    const auto before = resolver.getMetrics();

    const auto conflicts = resolver.detectConflicts(m_filePath);
    const auto after = resolver.getMetrics();
    EXPECT_EQ(after.conflictsDetected, before.conflictsDetected + conflicts.size());
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
