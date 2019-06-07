package dev.maxiv.fuzzer.http

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.output.CliktHelpFormatter
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.system.measureTimeMillis

@ExperimentalCoroutinesApi
fun main(args: Array<String>) {
    ProgramConfigurator().main(args)
}

@ExperimentalCoroutinesApi
class ProgramConfigurator : CliktCommand(name = "http-fuzzer") {
    init {
        context {
            helpFormatter =
                CliktHelpFormatter(showDefaultValues = true, showRequiredTag = true, requiredOptionMarker = "*")
        }
    }

    // Core settings
    val targetIP: String by option(
        "--target-ip",
        "--ip",
        help = "IP address of http(s) server",
        metavar = "IP"
    ).required()
    val baseDomain: String by option(help = "Base domain of site for bruteforcing", metavar = "URL").required()
    val dictionaryFile: String by option(
        help = "Path to dictionary file",
        metavar = "FILEPATH"
    ).default("dictionaries/alexaTop1mAXFRcommonSubdomains.txt")

    val debugFlag by option("--debug", help = "Enable debug").flag(default = false)

    // Extra configuration

    override fun run() {
        val dictionary = File(dictionaryFile).readLines()
        println("Loaded dictionary of ${dictionary.size} entries")

        val fuzzer = VirtualHostsFuzzer(targetIP, baseDomain, dictionary, debugEnabled = debugFlag)
        val measuredExecutionTime = measureTimeMillis {
            fuzzer.perform()
        }

        val measuredExecutionTimeSec = measuredExecutionTime / 1000.0

        println("Execution time is ${measuredExecutionTimeSec}")
        println("Average speed is ${dictionary.size / measuredExecutionTimeSec} subdomains/sec")
    }
}
