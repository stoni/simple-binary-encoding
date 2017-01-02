/*
 * Copyright 2016-2017 INAOS GmbH.
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

import static uk.co.real_logic.sbe.generation.c.CUtil.cTypeName;
import static uk.co.real_logic.sbe.generation.c.CUtil.dotsToUnderscore;
import static uk.co.real_logic.sbe.generation.c.CUtil.fromCamelCaseToUnderscore;
import static uk.co.real_logic.sbe.generation.c.CUtil.whitespaces;
import static uk.co.real_logic.sbe.generation.cpp.CppUtil.formatClassName;
import static uk.co.real_logic.sbe.ir.GenerationUtil.collectFields;
import static uk.co.real_logic.sbe.ir.GenerationUtil.collectGroups;
import static uk.co.real_logic.sbe.ir.GenerationUtil.collectVarData;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import org.agrona.Verify;
import org.agrona.generation.OutputManager;

import uk.co.real_logic.sbe.PrimitiveType;
import uk.co.real_logic.sbe.generation.CodeGenerator;
import uk.co.real_logic.sbe.ir.Encoding;
import uk.co.real_logic.sbe.ir.Ir;
import uk.co.real_logic.sbe.ir.Signal;
import uk.co.real_logic.sbe.ir.Token;

public class CGenerator implements CodeGenerator
{
    private static final String INDENT = "    ";
    private static final String NEWLINE = "\n";

    private final Ir ir;
    private final OutputManager outputManager;

    public CGenerator(final Ir ir, final OutputManager outputManager) throws IOException
    {
        Verify.notNull(ir, "ir");
        Verify.notNull(outputManager, "outputManager");

        this.ir = ir;
        this.outputManager = outputManager;
    }
    
    private CharSequence generateLiteral(final PrimitiveType type, final String value)
    {
        String literal = "";

        final String castType = cTypeName(type);
        switch (type)
        {
            case CHAR:
            case UINT8:
            case UINT16:
            case INT8:
            case INT16:
                literal = "(" + castType + ")" + value;
                break;

            case UINT32:
            case INT32:
                literal = value;
                break;

            case FLOAT:
                literal = value.endsWith("NaN") ? "SBE_FLOAT_NAN" : value + "f";
                break;

            case INT64:
                literal = value + "L";
                if (value.equals("-9223372036854775808"))
                {
                    literal = "INT64_MIN";
                }
                break;

            case UINT64:
                literal = "0x" + Long.toHexString(Long.parseLong(value)) + "L";
                break;

            case DOUBLE:
                literal = value.endsWith("NaN") ? "SBE_DOUBLE_NAN" : value;
                break;
        }

        return literal;
    }
    
    private CharSequence generateNullValueLiteral(final PrimitiveType primitiveType, final Encoding encoding)
    {
        /* Visual C++ does not handle minimum integer values properly
           See: http://msdn.microsoft.com/en-us/library/4kh09110.aspx
           So some of the null values get special handling */
        if (null == encoding.nullValue())
        {
            switch (primitiveType)
            {
                case CHAR:
                case FLOAT:
                case DOUBLE:
                    break; /* no special handling */
                case INT8:
                    return "SBE_NULLVALUE_INT8";
                case INT16:
                    return "SBE_NULLVALUE_INT16";
                case INT32:
                    return "SBE_NULLVALUE_INT32";
                case INT64:
                    return "SBE_NULLVALUE_INT64";
                case UINT8:
                    return "SBE_NULLVALUE_UINT8";
                case UINT16:
                    return "SBE_NULLVALUE_UINT16";
                case UINT32:
                    return "SBE_NULLVALUE_UINT32";
                case UINT64:
                    return "SBE_NULLVALUE_UINT64";
            }
        }

        return generateLiteral(primitiveType, encoding.applicableNullValue().toString());
    }
    
    public void generateHeaderAndIncludes(final StringBuilder sb)
	{
		final String includeName = ("sbe_"+dotsToUnderscore(ir.packageName())
			+"_"+ir.version()+"_h__").toUpperCase();
		
		sb.append("/* Generated SBE (Simple Binary Encoding) message codec */\n\n");

        sb.append(String.format(
            "#ifndef %1$s\n" +
            "#define %1$s\n\n" +
            "#include <sbe.h>\n\n",
            includeName));
	}
	
	public void generateMessageHeader(final StringBuilder sb)
	{
		final List<Token> tokens = ir.headerStructure().tokens();
		int encodedLength = tokens.get(0).encodedLength();
		int nameMax = 0;
		
		for (Token t : tokens)
		{
			if (t.signal() == Signal.ENCODING)
			{
				nameMax = Math.max(nameMax, 
						fromCamelCaseToUnderscore(t.name()).length());
			}
		}
		
		sb.append(String.format(
			"#define SBE_MESSAGE_HEADER_ENCODED_LENGTH" +
			INDENT + whitespaces(nameMax+1) + "%1$d\n",
			encodedLength
		));
		sb.append(NEWLINE);
		
		for (Token t : tokens)
		{
			if (t.signal() == Signal.ENCODING)
			{
				final String tname = fromCamelCaseToUnderscore(t.name());
				sb.append(String.format("#define " +
					"SBE_MESSAGE_HEADER_%1$s_NULL_VALUE" +
					INDENT + whitespaces(4+nameMax-tname.length()) +
					"%2$s" + NEWLINE, 
					tname.toUpperCase(),
					generateNullValueLiteral(t.encoding().primitiveType(), t.encoding()))
				);
				sb.append(String.format("#define " +
					"SBE_MESSAGE_HEADER_%1$s_MIN_VALUE" +
					INDENT + whitespaces(5+nameMax-tname.length()) +
					"%2$s" + NEWLINE, 
					tname.toUpperCase(),
					generateLiteral(t.encoding().primitiveType(), t.encoding().applicableMinValue().toString()))
				);
				sb.append(String.format("#define " +
					"SBE_MESSAGE_HEADER_%1$s_MAX_VALUE" +
					INDENT + whitespaces(5+nameMax-tname.length()) +
					"%2$s" + NEWLINE, 
					tname.toUpperCase(),
					generateLiteral(t.encoding().primitiveType(), t.encoding().applicableMaxValue().toString()))
				);
				sb.append(String.format("#define " +
					"SBE_MESSAGE_HEADER_%1$s_ENCODED_LENGTH" +
					INDENT + whitespaces(nameMax-tname.length()) +
					"%2$d" + NEWLINE, 
					tname.toUpperCase(),
					t.encodedLength())
				);
				sb.append(NEWLINE);
			}
		}
		
		sb.append("typedef struct sbe_message_header_s {\n");
		for (Token t : tokens)
		{
			if (t.signal() == Signal.ENCODING)
			{
				sb.append(INDENT);
				sb.append(cTypeName(t.encoding().primitiveType()));
				sb.append(" ");
				sb.append(fromCamelCaseToUnderscore(t.name()));
				sb.append(";");
				sb.append(NEWLINE);
			}
		}
	    sb.append("} sbe_message_header_t;\n");
	    sb.append(NEWLINE);
	    sb.append("int sbe_message_header_encode(char *buffer, \n" + 
	    		  "                              uint64_t offset, \n" +
	    		  "                              uint64_t buffer_length, \n" +
	    		  "                              sbe_message_header_t **m);");
	    sb.append(NEWLINE);
	    sb.append(NEWLINE);
	    sb.append("int sbe_message_header_decode(char *buffer, \n" + 
	    		  "                              uint64_t offset, \n" +
	    		  "                              uint64_t buffer_length, \n" +
	    		  "                              sbe_message_header_t **m);");
	    sb.append(NEWLINE);
	}
	
	public void generateMessage(final StringBuilder sb, final String messageName, Token msgToken, List<Token> msgFields)
	{
		final String structName = fromCamelCaseToUnderscore(messageName);
		sb.append(String.format("typedef struct sbe_%1$s_s {\n", structName));
		for (Token t : msgFields)
		{
			if (t.signal() == Signal.ENCODING)
			{
				sb.append(INDENT);
				sb.append(cTypeName(t.encoding().primitiveType()));
				sb.append(" ");
				sb.append(fromCamelCaseToUnderscore(t.name()));
				sb.append(";");
				sb.append(NEWLINE);
			}
		}
	    sb.append(String.format("} sbe_%1$s_t;\n", structName));
	}

	public void generate() throws IOException 
	{
		final String include_file = "sbe_"+dotsToUnderscore(ir.packageName())
			+"_"+ir.version()+".h";
		final String source_file = "sbe_"+dotsToUnderscore(ir.packageName())
			+"_"+ir.version()+".c";
		
		try (Writer out = outputManager.createOutput(include_file))
        {
			final StringBuilder sb = new StringBuilder();
			generateHeaderAndIncludes(sb);
			generateMessageHeader(sb);
			
			sb.append(NEWLINE);
			
			for (final List<Token> tokens : ir.messages())
	        {
	            final Token msgToken = tokens.get(0);
	            final String messageName = formatClassName(msgToken.name());
	            
	            final List<Token> messageBody = tokens.subList(1, tokens.size() - 1);
                int i = 0;

                final List<Token> fields = new ArrayList<>();
                i = collectFields(messageBody, i, fields);

                final List<Token> groups = new ArrayList<>();
                i = collectGroups(messageBody, i, groups);

                final List<Token> varData = new ArrayList<>();
                collectVarData(messageBody, i, varData);
	            
	            sb.append(messageName);
	            sb.append(NEWLINE);
	            generateMessage(sb, messageName, msgToken, fields);
	            sb.append(NEWLINE);
	        }
			
			out.append(sb.toString());
			out.append("\n");
			out.append("#endif\n");
        }
		
		try (Writer out = outputManager.createOutput(source_file))
        {
			
        }
		
	}
}
