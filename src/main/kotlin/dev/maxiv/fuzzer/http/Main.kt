package dev.maxiv.fuzzer.http

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import java.io.File

@ExperimentalCoroutinesApi
fun main(args: Array<String>) {
    ProgramConfigurator().main(args)

    //val targetIP = "188.166.8.136"; val baseDomain = "quckly.ru"
    //val targetIP = "64.233.162.100"; val baseDomain = "google.com"
    //val targetIP = "82.192.95.175"; val baseDomain = "habr.ru"
    //performFuzzing("5.255.255.5", "yandex.ru", listOf("lolkek", "mail"))

    //val fuzzDictionary = listOf("lolkek", "test1", "test2", "vk", "test3", "bans", "nb", "test4", "photos")
}

@ExperimentalCoroutinesApi
class ProgramConfigurator : CliktCommand(name = "http-fuzzer") {
    val targetIP: String by option(help = "IP address of http(s) server", metavar = "IP").required()
    val baseDomain: String by option(help = "Base domain of site for bruteforcing", metavar = "URL").required()
    val dictionaryFile: String by option(help = "Path to dictionary file", metavar = "FILEPATH").default("dictionaries/alexaTop1mAXFRcommonSubdomains.txt")

    val debugFlag by option("--debug", help = "Enable debug").flag(default = false)

        override fun run() {
        val dictionary = File(dictionaryFile).readLines()
        println("Loaded dictionary of ${dictionary.size} entries")

        val fuzzer = VirtualHostsFuzzer(targetIP, baseDomain, dictionary, debugEnabled = debugFlag)
        fuzzer.perform()
    }
}
