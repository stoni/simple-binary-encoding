/*
 * Copyright 2013-2017 Real Logic Ltd.
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
package uk.co.real_logic.sbe.generation;

import org.agrona.generation.PackageOutputManager;
import uk.co.real_logic.sbe.generation.cpp.CppGenerator;
import uk.co.real_logic.sbe.generation.cpp.NamespaceOutputManager;
import uk.co.real_logic.sbe.generation.golang.GolangGenerator;
import uk.co.real_logic.sbe.generation.golang.GolangOutputManager;
import uk.co.real_logic.sbe.generation.c.DirectoryOutputManager;
import uk.co.real_logic.sbe.generation.c.CGenerator;
import uk.co.real_logic.sbe.generation.java.JavaGenerator;
import uk.co.real_logic.sbe.ir.Ir;

import java.io.IOException;

import static uk.co.real_logic.sbe.SbeTool.*;

public enum TargetCodeGeneratorLoader implements TargetCodeGenerator
{
    JAVA()
    {
        public CodeGenerator newInstance(final Ir ir, final String outputDir) throws IOException
        {
            return new JavaGenerator(
                ir,
                System.getProperty(JAVA_ENCODING_BUFFER_TYPE, JAVA_DEFAULT_ENCODING_BUFFER_TYPE),
                System.getProperty(JAVA_DECODING_BUFFER_TYPE, JAVA_DEFAULT_DECODING_BUFFER_TYPE),
                Boolean.getBoolean(JAVA_GROUP_ORDER_ANNOTATION),
                Boolean.getBoolean(JAVA_GENERATE_INTERFACES),
                Boolean.getBoolean(DECODE_UNKNOWN_ENUM_VALUES),
                new PackageOutputManager(outputDir, ir.applicableNamespace()));
        }
    },
	
	C()
    {
        public CodeGenerator newInstance(final Ir ir, final String outputDir) throws IOException
        {
            return new CGenerator(ir, new DirectoryOutputManager(outputDir));
        }
    },

    CPP()
    {
        public CodeGenerator newInstance(final Ir ir, final String outputDir) throws IOException
        {
            return new CppGenerator(ir, new NamespaceOutputManager(outputDir, ir.applicableNamespace()));
        }
    },

    GOLANG()
    {
        public CodeGenerator newInstance(final Ir ir, final String outputDir) throws IOException
        {
            return new GolangGenerator(ir, new GolangOutputManager(outputDir, ir.applicableNamespace()));
        }
    };

    /**
     * Do a case insensitive lookup of a target language for code generation.
     *
     * @param name of the target language to lookup.
     * @return the {@link TargetCodeGenerator} for the given language name.
     */
    public static TargetCodeGenerator get(final String name)
    {
        for (final TargetCodeGeneratorLoader target : values())
        {
            if (target.name().equalsIgnoreCase(name))
            {
                return target;
            }
        }

        try
        {
            return (TargetCodeGenerator)Class.forName(name).newInstance();
        }
        catch (final Exception ex)
        {
            // do nothing and fall through
        }

        throw new IllegalArgumentException("No code generator for name: " + name);
    }
}
