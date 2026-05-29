from scanner.active.reflection import ReflectionContext, classify_reflection_contexts
from scanner.analysis.diffing import ResponseSnapshot, compare_responses


def test_response_diff_detects_marker_and_status_change() -> None:
    baseline = ResponseSnapshot("https://e.test", "https://e.test", 200, {}, b"<html>hello</html>")
    candidate = ResponseSnapshot("https://e.test?a=x", "https://e.test?a=x", 202, {}, b"<html>scanner-marker-abc</html>")
    diff = compare_responses(baseline, candidate, ("scanner-marker-abc",))
    assert diff.status_changed
    assert diff.reflected_markers == ("scanner-marker-abc",)


def test_reflection_context_classifier() -> None:
    html = '<div data-x="scanner-marker"></div><script>const a = "scanner-marker";</script>'
    contexts = classify_reflection_contexts(html, "scanner-marker")
    assert ReflectionContext.HTML_ATTRIBUTE in contexts
    assert ReflectionContext.JAVASCRIPT_STRING in contexts
