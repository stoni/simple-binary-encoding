/*
 * Copyright 2016 INAOS GmbH.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uk.co.real_logic.sbe.generation.c;

import static java.io.File.separatorChar;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;

import org.agrona.Verify;
import org.agrona.generation.OutputManager;

public class DirectoryOutputManager implements OutputManager
{

    private final File outputDir;

    /**
     * Create a new {@link OutputManager} for generating C 89 source files into a given package.
     *
     * @param baseDirectoryName for the generated source code.
     * @throws IOException if an error occurs during output
     */
    public DirectoryOutputManager(final String baseDirectoryName) throws IOException
    {
        Verify.notNull(baseDirectoryName, "baseDirectoryName");

        final String dirName =
            (baseDirectoryName.endsWith("" + separatorChar) ? baseDirectoryName : baseDirectoryName + separatorChar);

        outputDir = new File(dirName);
        if (!outputDir.exists() && !outputDir.mkdirs())
        {
            throw new IllegalStateException("Unable to create directory: " + dirName);
        }
    }

    /**
     * Create a new output which will be a C 89 source file in the given directory.
     *
     * The {@link java.io.Writer} should be closed once the caller has finished with it. The Writer is
     * buffer for efficient IO operations.
     *
     * @param name the name of the C header filename.
     * @return a {@link java.io.Writer} to which the source code should be written.
     */
    public Writer createOutput(String name) throws IOException
    {
        final File targetFile = new File(outputDir, name);
        return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(targetFile), "UTF-8"));
    }

}