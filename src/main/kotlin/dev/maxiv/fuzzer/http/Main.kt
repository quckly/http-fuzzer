package dev.maxiv.fuzzer.http

import kotlinx.coroutines.*

fun main() {
    val targetIP = "188.166.8.136"; val baseDomain = "quckly.ru"
    //val targetIP = "64.233.162.100"; val baseDomain = "google.com"
    //val targetIP = "82.192.95.175"; val baseDomain = "habr.ru"

    val fuzzDictionary = listOf("lolkek", "test1", "test2", "vk", "test3", "bans", "nb", "test4", "photos")

    performFuzzing(targetIP, baseDomain, fuzzDictionary)
    //performFuzzing("5.255.255.5", "yandex.ru", listOf("lolkek", "mail"))
}

fun performFuzzing(targetIP: String, baseDomain: String, dictionary: List<String>) {
    val fuzzer = VirtualHostsFuzzer(targetIP, baseDomain, dictionary)

    runBlocking {
        fuzzer.perform()
    }
}
