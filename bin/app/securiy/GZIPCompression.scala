package security;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.nio.charset.StandardCharsets.UTF_8;

object GZIPCompression {

  @throws(classOf[IOException])
  def compress(str: String): Array[Byte] = {
    if ((str == null) || (str.length == 0)) {
      return null;
    }
    val obj: ByteArrayOutputStream = new ByteArrayOutputStream();
    val gzip: GZIPOutputStream = new GZIPOutputStream(obj);
    gzip.write(str.getBytes());
    gzip.flush();
    gzip.close();
    return obj.toByteArray();
  }

  @throws(classOf[IOException])
  def decompress(compressed: Array[Byte]): String = {
    val outStr: StringBuilder = new StringBuilder();
    if ((compressed == null) || (compressed.size == 0)) {
      return "";
    }
    //val gis: GZIPInputStream = new GZIPInputStream(new ByteArrayInputStream(compressed));
    //val bufferedReader: BufferedReader = new BufferedReader(new InputStreamReader(gis, UTF_8));
    val inputStream = new GZIPInputStream(new ByteArrayInputStream(compressed))
        val output = scala.io.Source.fromInputStream(inputStream).mkString
        return output
    //return Iterator.continually(bufferedReader.readLine()).takeWhile(_ != null).mkString
  }
}
