package com.example.basespringbootapikotlin

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class SampleTest : FunSpec({
    test("simple math works") {
        (1 + 1) shouldBe 2
    }
})
