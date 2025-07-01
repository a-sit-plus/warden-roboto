package at.asitplus.attestation.android

import de.infix.testBalloon.framework.TestSuite


context(suite: TestSuite)
operator fun String.invoke(nested: () -> Unit) {
    suite.testSuite(this) { nested() }
}

context(suite: TestSuite)
infix operator fun String.minus(testBody: () -> Unit) {
    suite.test(this) { testBody() }
}

context(suite: TestSuite)
inline fun <reified T> withData(
    vararg data: T,
    nameFn: (T) -> String = { it.toString() },
    crossinline testBody:  (T) -> Unit
) {
    data.forEach { d ->
        suite.test(nameFn(d)) { testBody(d) }
    }
}
/*
context(suite: TestSuite)
fun <T> withData(data: Map<String, T>, testBody: suspend (T) -> Unit) {
    data.forEach { (name, d) ->
        suite.test(name) { testBody(d) }
    }
}
*/