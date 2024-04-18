/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.vau.lib.util;

import java.util.List;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ArrayUtils {

  public static byte[] unionByteArrays(Object... args) {
    final List<byte[]> byteArrayList = Stream.of(args)
      .map(arg -> {
        if (arg instanceof byte[] array) {
          return array;
        } else if (arg instanceof Byte b) {
          return new byte[]{b};
        } else {
          throw new RuntimeException("Invalid type " + arg.getClass().getSimpleName());
        }
      })
      .toList();

    int totalLength = byteArrayList.stream().mapToInt(array -> array.length).sum();
    byte[] result = new byte[totalLength];
    int offset = 0;
    for (byte[] array : byteArrayList) {
      System.arraycopy(array, 0, result, offset, array.length);
      offset += array.length;
    }
    return result;
  }
}
