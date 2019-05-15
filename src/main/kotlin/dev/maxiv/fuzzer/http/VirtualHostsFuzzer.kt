package dev.maxiv.fuzzer.http

import info.debatty.java.stringsimilarity.Jaccard
import io.ktor.client.HttpClient
import io.ktor.client.call.call
import io.ktor.client.engine.apache.Apache
import io.ktor.client.response.readText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import org.apache.http.config.RegistryBuilder
import org.apache.http.conn.DnsResolver
import org.apache.http.impl.conn.SystemDefaultDnsResolver
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor
import org.apache.http.impl.nio.reactor.IOReactorConfig
import org.apache.http.nio.conn.NHttpClientConnectionManager
import org.apache.http.nio.conn.NoopIOSessionStrategy
import org.apache.http.nio.conn.SchemeIOSessionStrategy
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy
import org.apache.http.ssl.SSLContextBuilder
import java.lang.Exception
import java.net.InetAddress
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext

data class VirtualHostTestResult(val virtualHost: String,
                                 val responseContent: String,
                                 val responseStatus: HttpStatusCode,
                                 val success: Boolean = true)

@ExperimentalCoroutinesApi
class VirtualHostsFuzzer(
    val targetIP: String,
    val baseDomain: String,
    val dictionary: List<String>,
    val method: String = "GET",
    val schema: String = "https",
    val path: String = "/",
    val userAgent: String = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
    val thresholdMultiplier: Double = 0.9,
    val randomHostsCount: Int = 5,
    val randomHostsLength: Int = 10,
    val maxConnections: Int = 50,
    val debugEnabled: Boolean = false
) {

    // https://github.com/tdebatty/java-string-similarity#shingle-n-gram-based-algorithms
    val similarityComputer = Jaccard()

    fun perform() {
        runBlocking {
            // Generate randoms string and calculate distance in not-existing hosts
            val responses: List<VirtualHostTestResult> = produceRandomStrings(randomHostsCount, randomHostsLength)
                .map { GlobalScope.async { testSubDomain(it) } }
                .toList() // Start iteration above all items in previously map
                .map { it.await() } // Wait for all results
                .toList()

            val responseToCheckSimilarity = responses[0]

            var maximumSimilarity = 1.0

            for (i in responses) {
                for (j in responses) {
                    val similarity = getSimilarity(i.responseContent, j.responseContent)

                    if (similarity > maximumSimilarity) {
                        maximumSimilarity = similarity
                    }

                    if (debugEnabled) {
                        println("Similarity of ${i.virtualHost} and ${j.virtualHost} = $similarity")
                    }
                }
            }

            // Move the upper limit of similarity down
            maximumSimilarity *= thresholdMultiplier

            println("Similarity threshold is $maximumSimilarity")
            if (!isOkStatusCode(responseToCheckSimilarity.responseStatus)) {
                println("Not existed virtual hosts have ${responseToCheckSimilarity.responseStatus.value} ${responseToCheckSimilarity.responseStatus.description} status code.")
            }
            println("Founded virtual hosts:")

            val jobsList = mutableListOf<Job>()

            for (testItem in dictionary) {
                // TODO: Launch sequentially
                jobsList.add(GlobalScope.launch {
                    val result = testSubDomain(testItem)

                    if (!result.success) {
                        return@launch
                    }

                    val similarity = getSimilarity(responseToCheckSimilarity.responseContent, result.responseContent)

                    // First compare status codes
                    // after compare content similarity
                    if (responseToCheckSimilarity.responseStatus != result.responseStatus ||
                        similarity < maximumSimilarity) {
                        // New virtual host found

                        println("Virtual Host found: $testItem ($similarity)")
                    }

                    // TODO: Debug
                    if (debugEnabled) {
                        println("Testing of $testItem is finished")
                    }
                })
            }

            jobsList.forEach { it.join() }

            println("Virtual Hosts Fuzzing is finished.")
        }
    }

    private suspend fun testSubDomain(testItem: String): VirtualHostTestResult {
        val requestURL = "$schema://$testItem.$baseDomain$path"

        try {
            val call = client.call(requestURL) {
                method = HttpMethod.parse(this@VirtualHostsFuzzer.method)
            }

            return VirtualHostTestResult(testItem, call.response.readText(), call.response.status)
        } catch (e: Exception) {
            // TODO: Add exception handler
            System.err.println("Error on $testItem: $e")
            return VirtualHostTestResult(testItem, "", HttpStatusCode.Conflict, false)
            //throw e
        }
    }

    private fun getSimilarity(str1: String, str2: String): Double =
        if (str1 == str2) 1.0 else similarityComputer.similarity(str1, str2)

    private fun isOkStatusCode(statusCode: HttpStatusCode): Boolean {
        return statusCode.value in 200..299
    }

    fun CoroutineScope.produceRandomStrings(count: Int, length: Int): ReceiveChannel<String> = produce {
        val charPool: List<Char> = ('a'..'z') + ('A'..'Z')// + ('0'..'9')

        for (x in 1..count) {
            val randomString = (1..length)
                .map { i -> kotlin.random.Random.nextInt(0, charPool.size) }
                .map(charPool::get)
                .joinToString("")

            send(randomString)
        }
    }

    /* Custom DNS resolver */
    var dnsResolver: DnsResolver = object : SystemDefaultDnsResolver() {
        override fun resolve(host: String): Array<InetAddress> {
            return arrayOf(InetAddress.getByName(targetIP))
        }
    }

    val client = HttpClient(Apache) {
        followRedirects = false

        engine {
            followRedirects =
                false  // Follow HTTP Location redirects - default false. It uses the default number of redirects defined by Apache's HttpClient that is 50.

            // For timeouts: 0 means infinite, while negative value mean to use the system's default value
            socketTimeout = 10_000  // Max time between TCP packets - default 10 seconds
            connectTimeout = 10_000 // Max time to establish an HTTP connection - default 10 seconds
            connectionRequestTimeout = -1//20_000 // Max time for the connection manager to start a request - 20 seconds

            customizeClient {
                // Accept all TLS certificates
                val builder = SSLContextBuilder()
                builder.loadTrustMaterial(null, { chain, authType -> true })
                val sslContext1 = builder.build()
                setSSLContext(sslContext1)
                //setSSLHostnameVerifier(org.apache.http.conn.ssl.NoopHostnameVerifier.INSTANCE)
                val hostnameVerifier = HostnameVerifier { s, sslSession -> true }
                setSSLHostnameVerifier(hostnameVerifier)

                // Change DNS Resolver and SSL
                val connmgr = createNHttpClientConnectionManager(hostnameVerifier, sslContext1, dnsResolver, maxConnections)
                setConnectionManager(connmgr)

                // From io.ktor.client.engine.apache.ApacheEngine
                setMaxConnPerRoute(maxConnections)
                setMaxConnTotal(maxConnections)

                // Change User-Agent
                setUserAgent(userAgent)
            }

            customizeRequest {
                // Apache's RequestConfig.Builder
                setMaxRedirects(1)
            }
        }
    }

    companion object {
        //private const val MAX_CONNECTIONS_COUNT = 1000
        private const val IO_THREAD_COUNT_DEFAULT = 4

        fun createNHttpClientConnectionManager(
            hostnameVerifier: HostnameVerifier,
            sslContext: SSLContext,
            dnsResolver: DnsResolver,
            maxConnections: Int
        ): NHttpClientConnectionManager {
            val sslStrategy: SchemeIOSessionStrategy
            val supportedProtocols = null
            val supportedCipherSuites = null

            sslStrategy = SSLIOSessionStrategy(
                sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifier
            )
            val ioreactor = DefaultConnectingIOReactor(IOReactorConfig.custom().apply {
                setIoThreadCount(IO_THREAD_COUNT_DEFAULT)
            }.build())

            val poolingmgr = PoolingNHttpClientConnectionManager(
                ioreactor,
                null,
                RegistryBuilder.create<SchemeIOSessionStrategy>()
                    .register("http", NoopIOSessionStrategy.INSTANCE)
                    .register("https", sslStrategy)
                    .build(),
                dnsResolver
            )

            poolingmgr.maxTotal = maxConnections
            poolingmgr.defaultMaxPerRoute = maxConnections

            return poolingmgr
        }
    }
}
