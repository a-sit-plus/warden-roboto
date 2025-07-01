package at.asitplus.attestation.android

import de.infix.testBalloon.framework.TestSuite


context(suite: TestSuite)
operator fun String.invoke(nested: () -> Unit) {
    suite.test(this) { nested() }
}

context(suite: TestSuite)
infix operator fun String.minus(testBody: () -> Unit) {
    suite.testSuite(this) { testBody() }
}

fun <Data> TestSuite.withData(vararg parameters: Data, action: suspend (Data) -> Unit) {
    for (data in parameters) {
        test("$data") {
            action(data)
        }
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