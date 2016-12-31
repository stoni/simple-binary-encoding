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

import static uk.co.real_logic.sbe.generation.c.CUtil.cppTypeName;
import static uk.co.real_logic.sbe.generation.c.CUtil.formatByteOrderEncoding;
import static uk.co.real_logic.sbe.generation.c.CUtil.formatStructName;
import static uk.co.real_logic.sbe.generation.c.CUtil.formatFunctionName;
import static uk.co.real_logic.sbe.generation.c.CUtil.toLowerFirstChar;
import static uk.co.real_logic.sbe.generation.c.CUtil.toUpperFirstChar;
import static uk.co.real_logic.sbe.generation.c.CUtil.fromCamelCaseToUnderscore;
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
    private static final String BASE_INDENT = "";
    private static final String INDENT = "    ";

    private final Ir ir;
    private final OutputManager outputManager;

    public CGenerator(final Ir ir, final OutputManager outputManager) throws IOException
    {
        Verify.notNull(ir, "ir");
        Verify.notNull(outputManager, "outputManager");

        this.ir = ir;
        this.outputManager = outputManager;
    }

    public void generateMessageHeaderStub() throws IOException
    {
        final String messageHeader = "message_header";

        try (Writer out = outputManager.createOutput(messageHeader))
        {
            final List<Token> tokens = ir.headerStructure().tokens();
            out.append(generateFileHeader(ir.namespaces(), messageHeader, null));
            out.append(generateFixedFlyweightCode(messageHeader, tokens.get(0).encodedLength()));
            out.append(generateCompositePropertyElements(
                messageHeader, tokens.subList(1, tokens.size() - 1), BASE_INDENT));
            out.append("#endif\n");
        }
    }

    public List<String> generateTypeStubs() throws IOException
    {
        final List<String> typesToInclude = new ArrayList<>();

        for (final List<Token> tokens : ir.types())
        {
            switch (tokens.get(0).signal())
            {
                case BEGIN_ENUM:
                    generateEnum(tokens);
                    break;

                case BEGIN_SET:
                    generateChoiceSet(tokens);
                    break;

                case BEGIN_COMPOSITE:
                    generateComposite(tokens);
                    break;
            }

            typesToInclude.add(tokens.get(0).name());
        }

        return typesToInclude;
    }

    public List<String> generateTypesToIncludes(final List<Token> tokens)
    {
        final List<String> typesToInclude = new ArrayList<>();

        for (final Token token : tokens)
        {
            switch (token.signal())
            {
                case BEGIN_ENUM:
                case BEGIN_SET:
                case BEGIN_COMPOSITE:
                    typesToInclude.add(token.name());
                    break;
            }
        }

        return typesToInclude;
    }

    public void generate() throws IOException
    {
        generateMessageHeaderStub();
        final List<String> typesToInclude = generateTypeStubs();

        for (final List<Token> tokens : ir.messages())
        {
            final Token msgToken = tokens.get(0);
            final String filename = fromCamelCaseToUnderscore(msgToken.name());
            final String className = msgToken.name();

            try (Writer out = outputManager.createOutput(filename))
            {
                out.append(generateFileHeader(ir.namespaces(), className, typesToInclude));
                out.append(generateMessageFlyweightCode(className, msgToken));

                final List<Token> messageBody = tokens.subList(1, tokens.size() - 1);
                int i = 0;

                final List<Token> fields = new ArrayList<>();
                i = collectFields(messageBody, i, fields);

                final List<Token> groups = new ArrayList<>();
                i = collectGroups(messageBody, i, groups);

                final List<Token> varData = new ArrayList<>();
                collectVarData(messageBody, i, varData);

                final StringBuilder sb = new StringBuilder();
                out.append(generateFields(className, fields, BASE_INDENT));
                generateGroups(sb, groups, BASE_INDENT);
                out.append(sb);
                out.append(generateVarData(className, varData, BASE_INDENT));
                out.append("#endif\n");
            }
        }
    }

    private void generateGroups(final StringBuilder sb, final List<Token> tokens, final String indent)
    {
        for (int i = 0, size = tokens.size(); i < size; i++)
        {
            final Token groupToken = tokens.get(i);
            if (groupToken.signal() != Signal.BEGIN_GROUP)
            {
                throw new IllegalStateException("tokens must begin with BEGIN_GROUP: token=" + groupToken);
            }

            final String groupName = groupToken.name();
            final String cppTypeForNumInGroup = cppTypeName(tokens.get(i + 3).encoding().primitiveType());

            generateGroupClassHeader(sb, groupName, tokens, i, indent + INDENT);

            ++i;
            final int groupHeaderTokenCount = tokens.get(i).componentTokenCount();
            i += groupHeaderTokenCount;

            final List<Token> fields = new ArrayList<>();
            i = collectFields(tokens, i, fields);
            sb.append(generateFields(groupName, fields, indent + INDENT));

            final List<Token> groups = new ArrayList<>();
            i = collectGroups(tokens, i, groups);
            generateGroups(sb, groups, indent + INDENT);

            final List<Token> varData = new ArrayList<>();
            i = collectVarData(tokens, i, varData);
            sb.append(generateVarData(formatStructName(groupName), varData, indent + INDENT));

            sb.append(indent).append("    };\n");
            sb.append(generateGroupProperty(groupName, groupToken, cppTypeForNumInGroup, indent));
        }
    }

    private static void generateGroupClassHeader(
        final StringBuilder sb, final String groupName, final List<Token> tokens, final int index, final String indent)
    {
        final String dimensionsClassName = formatStructName(tokens.get(index + 1).name());
        final int dimensionHeaderLength = tokens.get(index + 1).encodedLength();

        final int blockLength = tokens.get(index).encodedLength();
        final Token numInGroupToken = tokens.get(index + 3);
        final String cppTypeForBlockLength = cppTypeName(tokens.get(index + 2).encoding().primitiveType());
        final String cppTypeForNumInGroup = cppTypeName(numInGroupToken.encoding().primitiveType());

        sb.append(String.format(
            "\n" +
            indent + "class %1$s\n" +
            indent + "{\n" +
            indent + "private:\n" +
            indent + "    char *m_buffer;\n" +
            indent + "    std::uint64_t m_bufferLength;\n" +
            indent + "    std::uint64_t *m_positionPtr;\n" +
            indent + "    std::uint64_t m_blockLength;\n" +
            indent + "    std::uint64_t m_count;\n" +
            indent + "    std::uint64_t m_index;\n" +
            indent + "    std::uint64_t m_offset;\n" +
            indent + "    std::uint64_t m_actingVersion;\n" +
            indent + "    %2$s m_dimensions;\n\n" +
            indent + "public:\n\n",
            formatStructName(groupName), dimensionsClassName));

        sb.append(String.format(
            indent + "    inline void wrapForDecode(char *buffer, std::uint64_t *pos, const std::uint64_t actingVersion," +
                " const std::uint64_t bufferLength)\n" +
            indent + "    {\n" +
            indent + "        m_buffer = buffer;\n" +
            indent + "        m_bufferLength = bufferLength;\n" +
            indent + "        m_dimensions.wrap(m_buffer, *pos, actingVersion, bufferLength);\n" +
            indent + "        m_blockLength = m_dimensions.blockLength();\n" +
            indent + "        m_count = m_dimensions.numInGroup();\n" +
            indent + "        m_index = -1;\n" +
            indent + "        m_actingVersion = actingVersion;\n" +
            indent + "        m_positionPtr = pos;\n" +
            indent + "        *m_positionPtr = *m_positionPtr + %1$d;\n" +
            indent + "    }\n\n",
            dimensionHeaderLength));

        sb.append(String.format(
            indent + "    inline void wrapForEncode(char *buffer, const %3$s count," +
                " std::uint64_t *pos, const std::uint64_t actingVersion, const std::uint64_t bufferLength)\n" +
            indent + "    {\n" +
            indent + "        if (count < %5$d || count > %6$d)\n" +
            indent + "        {\n" +
            indent + "            throw std::runtime_error(\"count outside of allowed range [E110]\");\n" +
            indent + "        }\n" +
            indent + "        m_buffer = buffer;\n" +
            indent + "        m_bufferLength = bufferLength;\n" +
            indent + "        m_dimensions.wrap(m_buffer, *pos, actingVersion, bufferLength);\n" +
            indent + "        m_dimensions.blockLength((%1$s)%2$d);\n" +
            indent + "        m_dimensions.numInGroup((%3$s)count);\n" +
            indent + "        m_index = -1;\n" +
            indent + "        m_count = count;\n" +
            indent + "        m_blockLength = %2$d;\n" +
            indent + "        m_actingVersion = actingVersion;\n" +
            indent + "        m_positionPtr = pos;\n" +
            indent + "        *m_positionPtr = *m_positionPtr + %4$d;\n" +
            indent + "    }\n\n",
            cppTypeForBlockLength, blockLength, cppTypeForNumInGroup, dimensionHeaderLength,
            numInGroupToken.encoding().applicableMinValue().longValue(),
            numInGroupToken.encoding().applicableMaxValue().longValue()));

        sb.append(String.format(
            indent + "    static SBE_CONSTEXPR const std::uint64_t sbeHeaderSize()\n" +
            indent + "    {\n" +
            indent + "        return %1$d;\n" +
            indent + "    }\n\n" +
            indent + "    static SBE_CONSTEXPR const std::uint64_t sbeBlockLength()\n" +
            indent + "    {\n" +
            indent + "        return %2$d;\n" +
            indent + "    }\n\n" +
            indent + "    std::uint64_t position(void) const\n" +
            indent + "    {\n" +
            indent + "        return *m_positionPtr;\n" +
            indent + "    }\n\n" +
            indent + "    void position(const std::uint64_t position)\n" +
            indent + "    {\n" +
            indent + "        if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))\n" +
            indent + "        {\n" +
            indent + "             throw std::runtime_error(\"buffer too short [E100]\");\n" +
            indent + "        }\n" +
            indent + "        *m_positionPtr = position;\n" +
            indent + "    }\n\n" +
            indent + "    inline std::uint64_t count(void) const\n" +
            indent + "    {\n" +
            indent + "        return m_count;\n" +
            indent + "    }\n\n" +
            indent + "    inline bool hasNext(void) const\n" +
            indent + "    {\n" +
            indent + "        return m_index + 1 < m_count;\n" +
            indent + "    }\n\n" +
            indent + "    inline %3$s &next(void)\n" +
            indent + "    {\n" +
            indent + "        m_offset = *m_positionPtr;\n" +
            indent + "        if (SBE_BOUNDS_CHECK_EXPECT(( (m_offset + m_blockLength) > m_bufferLength ), false))\n" +
            indent + "        {\n" +
            indent + "            throw std::runtime_error(\"buffer too short to support next group index [E108]\");\n" +
            indent + "        }\n" +
            indent + "        *m_positionPtr = m_offset + m_blockLength;\n" +
            indent + "        ++m_index;\n\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            dimensionHeaderLength, blockLength, formatStructName(groupName)));

        sb.append(String.format(
            indent + "#if __cplusplus < 201103L\n" +
            indent + "    template<class Func> inline void forEach(Func& func)\n" +
            indent + "    {\n" +
            indent + "        while(hasNext())\n" +
            indent + "        {\n" +
            indent + "            next(); func(*this);\n" +
            indent + "        }\n" +
            indent + "    }\n\n" +
            indent + "#else\n" +
            indent + "    template<class Func> inline void forEach(Func&& func)\n" +
            indent + "    {\n" +
            indent + "        while(hasNext())\n" +
            indent + "        {\n" +
            indent + "            next(); func(*this);\n" +
            indent + "        }\n" +
            indent + "    }\n\n" +
            indent + "#endif\n\n",
            formatStructName(groupName)));
    }

    private static CharSequence generateGroupProperty(
        final String groupName, final Token token, final String cppTypeForNumInGroup, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final String className = formatStructName(groupName);
        final String propertyName = formatFunctionName(groupName);

        sb.append(String.format(
            "\n" +
            "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            "public:\n",
            className,
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    static SBE_CONSTEXPR const std::uint16_t %1$sId(void)\n" +
            indent + "    {\n" +
            indent + "        return %2$d;\n" +
            indent + "    }\n\n",
            groupName,
            (long)token.id()
        ));

        sb.append(String.format(
            "\n" +
            indent + "    inline %1$s &%2$s(void)\n" +
            indent + "    {\n" +
            indent + "        m_%2$s.wrapForDecode(m_buffer, m_positionPtr, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            className,
            propertyName
        ));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s &%2$sCount(const %3$s count)\n" +
            indent + "    {\n" +
            indent + "        m_%2$s.wrapForEncode(m_buffer, count, m_positionPtr, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n\n",
            className,
            propertyName,
            cppTypeForNumInGroup
        ));

        sb.append(String.format(
            indent + "    static SBE_CONSTEXPR const std::uint64_t %1$sSinceVersion(void)\n" +
            indent + "    {\n" +
            indent + "         return %2$d;\n" +
            indent + "    }\n\n" +
            indent + "    bool %1$sInActingVersion(void)\n" +
            indent + "    {\n" +
            indent + "#pragma GCC diagnostic push\n" +
            indent + "#pragma GCC diagnostic ignored \"-Wtautological-compare\"\n" +
            indent + "        return m_actingVersion >= %1$sSinceVersion();\n" +
            indent + "#pragma GCC diagnostic pop\n" +
            indent + "    }\n",
            propertyName,
            (long)token.version()));

        return sb;
    }

    private CharSequence generateVarData(final String className, final List<Token> tokens, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0, size = tokens.size(); i < size;)
        {
            final Token token = tokens.get(i);
            if (token.signal() != Signal.BEGIN_VAR_DATA)
            {
                throw new IllegalStateException("tokens must begin with BEGIN_VAR_DATA: token=" + token);
            }

            final String propertyName = toUpperFirstChar(token.name());
            final String characterEncoding = tokens.get(i + 3).encoding().characterEncoding();
            final Token lengthToken = tokens.get(i + 2);
            final int lengthOfLengthField = lengthToken.encodedLength();
            final String lengthCppType = cppTypeName(lengthToken.encoding().primitiveType());

            generateFieldMetaAttributeMethod(sb, className, token, indent);

            generateVarDataDescriptors(
                sb, className, token, propertyName, characterEncoding, lengthToken, lengthOfLengthField, lengthCppType, indent);

            sb.append(String.format(
                indent + "const char *%1$s(void)\n" +
                indent + "{\n" +
                    "%2$s" +
                indent + "     const char *fieldPtr = (m_buffer + position() + %3$d);\n" +
                indent + "     position(position() + %3$d + *((%4$s *)(m_buffer + position())));\n" +
                indent + "     return fieldPtr;\n" +
                indent + "}\n\n",
                formatFunctionName(propertyName),
                generateTypeFieldNotPresentCondition(token.version(), BASE_INDENT),
                lengthOfLengthField,
                lengthCppType
            ));

            sb.append(String.format(
                indent + "uint64_t get_%1$s(char *dst, const uint64_t length)\n" +
                indent + "{\n" +
                    "%2$s" +
                indent + "    uint64_t lengthOfLengthField = %3$d;\n" +
                indent + "    uint64_t lengthPosition = position();\n" +
                indent + "    position(lengthPosition + lengthOfLengthField);\n" +
                indent + "    uint64_t dataLength = %4$s(*((%5$s *)(m_buffer + lengthPosition)));\n" +
                indent + "    uint64_t bytesToCopy = (length < dataLength) ? length : dataLength;\n" +
                indent + "    uint64_t pos = position();\n" +
                indent + "    position(position() + dataLength);\n" +
                indent + "    memcpy(dst, m_buffer + pos, bytesToCopy);\n" +
                indent + "    return bytesToCopy;\n" +
                indent + "}\n\n",
                fromCamelCaseToUnderscore(propertyName),
                generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
                lengthOfLengthField,
                formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                lengthCppType
            ));

            sb.append(String.format(
                indent + "void put_%1$s(const char *src, const %3$s length, %5$s_t **target)\n" +
                indent + "{\n" +
                indent + "    uint64_t lengthOfLengthField = %2$d;\n" +
                indent + "    uint64_t lengthPosition = position();\n" +
                indent + "    position(lengthPosition + lengthOfLengthField);\n" +
                indent + "    *((%3$s *)(m_buffer + lengthPosition)) = %4$s(length);\n" +
                indent + "    uint64_t pos = position();\n" +
                indent + "    position(position() + length);\n" +
                indent + "    memcpy(m_buffer + pos, src, length);\n" +
                indent + "    return *this;\n" +
                indent + "}\n\n",
                fromCamelCaseToUnderscore(propertyName),
                lengthOfLengthField,
                lengthCppType,
                formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                fromCamelCaseToUnderscore(className)
            ));

            sb.append(String.format(
                indent + "void get_%1$s_as_string(char **str)\n" +
                indent + "{\n" +
                "%2$s" +
                indent + "    uint64_t lengthOfLengthField = %3$d;\n" +
                indent + "    uint64_t lengthPosition = position();\n" +
                indent + "    position(lengthPosition + lengthOfLengthField);\n" +
                indent + "    uint64_t dataLength = %4$s(*((%5$s *)(m_buffer + lengthPosition)));\n" +
                indent + "    uint64_t pos = position();\n" +
                indent + "    char *result(m_buffer + pos, dataLength);\n" +
                indent + "    position(position() + dataLength);\n" +
                indent + "    *str = result;\n" +
                indent + "}\n\n",
                fromCamelCaseToUnderscore(propertyName),
                generateStringNotPresentCondition(token.version(), BASE_INDENT),
                lengthOfLengthField,
                formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                lengthCppType
            ));

            sb.append(String.format(
                indent + "void put_%2$s(const char *str, %1$s_t **target)\n" +
                indent + "{\n" +
                indent + "    if (str.length() > %6$d) {\n" +
                indent + "         /* FIXME: error handling (string length too long for length type [E109]) */\n" +
                indent + "    }\n" +
                indent + "    uint64_t lengthOfLengthField = %3$d;\n" +
                indent + "    uint64_t lengthPosition = position();\n" +
                indent + "    position(lengthPosition + lengthOfLengthField);\n" +
                indent + "    *((%4$s *)(m_buffer + lengthPosition)) = %5$s((%4$s)str.length());\n" +
                indent + "    uint64_t pos = position();\n" +
                indent + "    position(position() + str.length());\n" +
                indent + "    memcpy(m_buffer + pos, str.c_str(), str.length());\n" +
                indent + "    return *this;\n" +
                indent + "}\n",
                fromCamelCaseToUnderscore(className),
                fromCamelCaseToUnderscore(propertyName),
                lengthOfLengthField,
                lengthCppType,
                formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
                lengthToken.encoding().applicableMaxValue().longValue()
            ));

            i += token.componentTokenCount();
        }

        return sb;
    }

    private void generateVarDataDescriptors(
        final StringBuilder sb,
        final String className,
        final Token token,
        final String propertyName,
        final String characterEncoding,
        final Token lengthToken,
        final Integer sizeOfLengthField,
        final String lengthCppType,
        final String indent)
    {
        sb.append(String.format(
            "\n"  +
            indent + "static const char *sbe_%3$s_%1$s_character_encoding()\n" +
            indent + "{\n" +
            indent + "    return \"%2$s\";\n" +
            indent + "}\n\n",
            fromCamelCaseToUnderscore(toLowerFirstChar(propertyName)),
            characterEncoding,
            fromCamelCaseToUnderscore(className)
        ));

        sb.append(String.format(
            indent + "static uint64_t sbe_%4$s_%1$s_since_version(sbe_%4$s_t *%4$s)\n" +
            indent + "{\n" +
            indent + "    return %2$d;\n" +
            indent + "}\n\n" +
            indent + "int sbe_%4$s_%1$s_in_acting_version()\n" +
            indent + "{\n" +
            indent + "    return %4$s->acting_version >= %1$s_since_version();\n" +
            indent + "}\n\n" +
            indent + "static uint16_t sbe_%4$s_%1$s_id()\n" +
            indent + "{\n" +
            indent + "    return %3$d;\n" +
            indent + "}\n",
            fromCamelCaseToUnderscore(toLowerFirstChar(propertyName)),
            (long)token.version(),
            token.id(),
            fromCamelCaseToUnderscore(className)
        ));

        sb.append(String.format(
            "\n" +
            indent + "static uint64_t sbe_%2$s_%1$s_header_length()\n" +
            indent + "{\n" +
            indent + "    return %3$d;\n" +
            indent + "}\n",
            fromCamelCaseToUnderscore(toLowerFirstChar(propertyName)),
            fromCamelCaseToUnderscore(className),
            sizeOfLengthField
        ));

        sb.append(String.format(
            "\n" +
            indent + "%4$s %1$s_length(void) const\n" +
            indent + "{\n" +
            "%2$s" +
            indent + "    return %3$s(*((%4$s *)(m_buffer + position())));\n" +
            indent + "}\n\n",
            fromCamelCaseToUnderscore(toLowerFirstChar(propertyName)),
            generateArrayFieldNotPresentCondition(token.version(), BASE_INDENT),
            formatByteOrderEncoding(lengthToken.encoding().byteOrder(), lengthToken.encoding().primitiveType()),
            lengthCppType
        ));
    }

    private void generateChoiceSet(final List<Token> tokens) throws IOException
    {
        final String bitSetName = formatStructName(tokens.get(0).name());
        final String filename = fromCamelCaseToUnderscore(tokens.get(0).name());

        try (Writer out = outputManager.createOutput(filename))
        {
            out.append(generateFileHeader(ir.namespaces(), bitSetName, null));
            out.append(generateFixedFlyweightCode(bitSetName, tokens.get(0).encodedLength()));

            out.append(String.format(
                "\n" +
                "    %1$s &clear(void)\n" +
                "    {\n" +
                "        *((%2$s *)(m_buffer + m_offset)) = 0;\n" +
                "        return *this;\n" +
                "    }\n\n",
                bitSetName,
                cppTypeName(tokens.get(0).encoding().primitiveType())
            ));

            out.append(generateChoices(bitSetName, tokens.subList(1, tokens.size() - 1)));
            out.append("#endif\n");
        }
    }

    private void generateEnum(final List<Token> tokens) throws IOException
    {
        final Token enumToken = tokens.get(0);
        final String enumName = formatStructName(tokens.get(0).name());
        final String filename = fromCamelCaseToUnderscore(tokens.get(0).name());

        try (Writer out = outputManager.createOutput(filename))
        {
            out.append(generateFileHeader(ir.namespaces(), enumName, null));

            out.append(generateEnumValues(tokens.get(0).name(), tokens.subList(1, tokens.size() - 1), enumToken));

            out.append(generateEnumLookupMethod(tokens.subList(1, tokens.size() - 1), enumToken));

            out.append("#endif\n");
        }
    }

    private void generateComposite(final List<Token> tokens) throws IOException
    {
        final String compositeStructName = formatStructName(tokens.get(0).name());
        final String compositeName = fromCamelCaseToUnderscore(tokens.get(0).name());
        final String filename = fromCamelCaseToUnderscore(tokens.get(0).name());

        try (Writer out = outputManager.createOutput(filename))
        {
            out.append(generateFileHeader(ir.namespaces(), compositeStructName,
                generateTypesToIncludes(tokens.subList(1, tokens.size() - 1))));
            out.append(generateFixedFlyweightCode(compositeName, tokens.get(0).encodedLength()));

            out.append(generateCompositePropertyElements(compositeName, tokens.subList(1, tokens.size() - 1), BASE_INDENT));

            out.append("#endif\n");
        }
    }

    private static CharSequence generateChoiceNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return false;\n" +
            indent + "        }\n\n",
            sinceVersion
        );
    }

    private CharSequence generateChoices(final String bitsetClassName, final List<Token> tokens)
    {
        final StringBuilder sb = new StringBuilder();

        tokens
            .stream()
            .filter((token) -> token.signal() == Signal.CHOICE)
            .forEach(
                (token) ->
                {
                    final String choiceName = formatFunctionName(token.name());
                    final String typeName = cppTypeName(token.encoding().primitiveType());
                    final String choiceBitPosition = token.encoding().constValue().toString();
                    final String byteOrderStr = formatByteOrderEncoding(
                        token.encoding().byteOrder(), token.encoding().primitiveType());

                    sb.append(String.format(
                        "\n" +
                        "    bool %1$s(void) const\n" +
                        "    {\n" +
                        "%2$s" +
                        "        return %3$s(*((%4$s *)(m_buffer + m_offset))) & (0x1L << %5$s);\n" +
                        "    }\n\n",
                        choiceName,
                        generateChoiceNotPresentCondition(token.version(), BASE_INDENT),
                        byteOrderStr,
                        typeName,
                        choiceBitPosition
                    ));

                    sb.append(String.format(
                        "    %1$s &%2$s(const bool value)\n" +
                        "    {\n" +
                        "        %3$s bits = %4$s(*((%3$s *)(m_buffer + m_offset)));\n" +
                        "        bits = value ? (bits | (0x1L << %5$s)) : (bits & ~(0x1L << %5$s));\n" +
                        "        *((%3$s *)(m_buffer + m_offset)) = %4$s(bits);\n" +
                        "        return *this;\n" +
                        "    }\n",
                        bitsetClassName,
                        choiceName,
                        typeName,
                        byteOrderStr,
                        choiceBitPosition
                    ));
                });

        return sb;
    }

    private CharSequence generateEnumValues(final String name, final List<Token> tokens, final Token encodingToken)
    {
        final StringBuilder sb = new StringBuilder();
        final Encoding encoding = encodingToken.encoding();

        sb.append(String.format(
            "typedef enum sbe_%1$s_e {\n",
            fromCamelCaseToUnderscore(name)
        ));

        for (final Token token : tokens)
        {
            final CharSequence constVal = generateLiteral(
                token.encoding().primitiveType(), token.encoding().constValue().toString());
            sb.append("    ").append(token.name()).append(" = ").append(constVal).append(",\n");
        }

        sb.append(String.format(
            "    NULL_VALUE = %1$s",
            generateLiteral(encoding.primitiveType(), encoding.applicableNullValue().toString())
        ));

        sb.append(String.format("\n} sbe_%1$s_t;\n\n", fromCamelCaseToUnderscore(name)));

        return sb;
    }

    private static CharSequence generateEnumLookupMethod(final List<Token> tokens, final Token encodingToken)
    {
        final String enumName = formatStructName(encodingToken.name());
        final String funcNamePart = fromCamelCaseToUnderscore(encodingToken.name());
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "%1$s sbe_get_%3$s(%2$s value)\n" +
            "{\n" +
            "    switch (value)\n" +
            "    {\n",
            enumName,
            cppTypeName(tokens.get(0).encoding().primitiveType()),
            funcNamePart
        ));

        for (final Token token : tokens)
        {
            sb.append(String.format(
                "        case %1$s: return %2$s;\n",
                token.encoding().constValue().toString(),
                token.name())
            );
        }

        sb.append(String.format(
            "        case %1$s: return NULL_VALUE;\n" +
            "    }\n\n" +
            "    /* FIXME: (\"unknown value for enum %2$s [E103]\"); */\n" +
            "}\n",
            encodingToken.encoding().applicableNullValue().toString(),
            enumName
        ));

        return sb;
    }

    private CharSequence generateFieldNotPresentCondition(final int sinceVersion, final Encoding encoding, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return %2$s;\n" +
            indent + "        }\n\n",
            sinceVersion,
            generateLiteral(encoding.primitiveType(), encoding.applicableNullValue().toString()));
    }

    private static CharSequence generateArrayFieldNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return 0;\n" +
            indent + "        }\n\n",
            sinceVersion);
    }

    private static CharSequence generateStringNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return std::string(\"\");\n" +
            indent + "        }\n\n",
            sinceVersion);
    }

    private static CharSequence generateTypeFieldNotPresentCondition(final int sinceVersion, final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return nullptr;\n" +
            indent + "        }\n\n",
            sinceVersion);
    }

    private static CharSequence generateFileHeader(
        final CharSequence[] namespaces,
        final String className,
        final List<String> typesToInclude)
    {
        final StringBuilder sb = new StringBuilder();
        String includeName = fromCamelCaseToUnderscore(className).toUpperCase();
        if (!className.toLowerCase().startsWith("sbe_"))
        {
            includeName = "SBE_" + includeName;
        }

        sb.append("/* Generated SBE (Simple Binary Encoding) message codec */\n");

        sb.append(String.format(
            "#ifndef %1$s_H_\n" +
            "#define %1$s_H_\n\n" +

            "/* math.h needed for NAN */\n" +
            "#include <math.h>\n" +
            "#define SBE_FLOAT_NAN NAN\n" +
            "#define SBE_DOUBLE_NAN NAN\n" +
            "#include <sbe.h>\n\n",
            includeName));

        if (typesToInclude != null)
        {
            for (final String incName : typesToInclude)
            {
                sb.append(String.format(
                    "#include \"%1$s.h\"\n",
                    fromCamelCaseToUnderscore(incName)));
            }
            sb.append("\n");
        }

        return sb;
    }

    private CharSequence generateCompositePropertyElements(
        final String containingClassName, final List<Token> tokens, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < tokens.size();)
        {
            final Token token = tokens.get(i);
            final String functionName = formatFunctionName(token.name());

            switch (token.signal())
            {
                case ENCODING:
                    sb.append(generatePrimitiveProperty(containingClassName, functionName, token, indent));
                    break;

                case BEGIN_ENUM:
                    sb.append(generateEnumProperty(containingClassName, token, functionName, token, indent));
                    break;

                case BEGIN_SET:
                    sb.append(generateBitsetProperty(functionName, token, indent));
                    break;

                case BEGIN_COMPOSITE:
                    sb.append(generateCompositeProperty(functionName, token, indent));
                    break;
            }

            i += tokens.get(i).componentTokenCount();
        }

        return sb;
    }

    private CharSequence generatePrimitiveProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        sb.append(generatePrimitiveFieldMetaData(containingClassName, propertyName, token, indent));

        if (token.isConstantEncoding())
        {
            sb.append(generateConstPropertyMethods(propertyName, token, indent));
        }
        else
        {
            sb.append(generatePrimitivePropertyMethods(containingClassName, propertyName, token, indent));
        }

        return sb;
    }

    private CharSequence generatePrimitivePropertyMethods(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final int arrayLength = token.arrayLength();

        if (arrayLength == 1)
        {
            return generateSingleValueProperty(containingClassName, propertyName, token, indent);
        }
        else if (arrayLength > 1)
        {
            return generateArrayProperty(containingClassName, propertyName, token, indent);
        }

        return "";
    }

    private CharSequence generatePrimitiveFieldMetaData(final String className, final String propertyName,
                                                        final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final Encoding encoding = token.encoding();
        final PrimitiveType primitiveType = encoding.primitiveType();
        final String cppTypeName = cppTypeName(primitiveType);
        final CharSequence nullValueString = generateNullValueLiteral(primitiveType, encoding);

        sb.append(String.format(
            "\n" +
            indent + "static %1$s sbe_%4$s_%2$s_null_value()\n" +
            indent + "{\n" +
            indent + "    return %3$s;\n" +
            indent + "}\n",
            cppTypeName,
            propertyName,
            nullValueString,
            fromCamelCaseToUnderscore(className)));

        sb.append(String.format(
            "\n" +
            indent + "static %1$s sbe_%4$s_%2$s_min_value()\n" +
            indent + "{\n" +
            indent + "    return %3$s;\n" +
            indent + "}\n",
            cppTypeName,
            propertyName,
            generateLiteral(primitiveType, token.encoding().applicableMinValue().toString()),
            fromCamelCaseToUnderscore(className)));

        sb.append(String.format(
            "\n" +
            indent + "static %1$s sbe_%4$s_%2$s_max_Value()\n" +
            indent + "{\n" +
            indent + "    return %3$s;\n" +
            indent + "}\n",
            cppTypeName,
            propertyName,
            generateLiteral(primitiveType, token.encoding().applicableMaxValue().toString()),
            fromCamelCaseToUnderscore(className)));

        return sb;
    }

    private CharSequence generateSingleValueProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cppTypeName = cppTypeName(token.encoding().primitiveType());
        final int offset = token.offset();
        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "%1$s sbe_message_header_%2$s(sbe_%6$s_t *message_header)\n" +
            indent + "{\n" +
                "%3$s" +
            indent + "    return %4$s(*((%1$s *)(message_header->buffer + message_header->offset + %5$d)));\n" +
            indent + "}\n",
            cppTypeName,
            propertyName,
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset,
            containingClassName));

        return sb;
    }

    private CharSequence generateArrayProperty(
        final String containingClassName, final String propertyName, final Token token, final String indent)
    {
        final String cppTypeName = cppTypeName(token.encoding().primitiveType());
        final int offset = token.offset();

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            indent + "    static const std::uint64_t %1$sLength(void)\n" +
            indent + "    {\n" +
            indent + "        return %2$d;\n" +
            indent + "    }\n\n",
            propertyName,
            token.arrayLength()));

        sb.append(String.format(
            indent + "    const char *%1$s(void) const\n" +
            indent + "    {\n" +
                              "%2$s" +
            indent + "        return (m_buffer + m_offset + %3$d);\n" +
            indent + "    }\n\n",
            propertyName,
            generateTypeFieldNotPresentCondition(token.version(), indent),
            offset));

        sb.append(String.format(
            indent + "    %1$s %2$s(const std::uint64_t index) const\n" +
            indent + "    {\n" +
            indent + "        if (index >= %3$d)\n" +
            indent + "        {\n" +
            indent + "            throw std::runtime_error(\"index out of range for %2$s [E104]\");\n" +
            indent + "        }\n\n" +
                "%4$s" +
            indent + "        return %5$s(*((%1$s *)(m_buffer + m_offset + %6$d + (index * %7$d))));\n" +
            indent + "    }\n\n",
            cppTypeName,
            propertyName,
            token.arrayLength(),
            generateFieldNotPresentCondition(token.version(), token.encoding(), indent),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
            offset,
            token.encoding().primitiveType().size()));

        sb.append(String.format(
            indent + "    void %1$s(const std::uint64_t index, const %2$s value)\n" +
            indent + "    {\n" +
            indent + "        if (index >= %3$d)\n" +
            indent + "        {\n" +
            indent + "            throw std::runtime_error(\"index out of range for %1$s [E105]\");\n" +
            indent + "        }\n\n" +
            indent + "        *((%2$s *)(m_buffer + m_offset + %4$d + (index * %5$d))) = %6$s(value);\n" +
            indent + "    }\n\n",
            propertyName,
            cppTypeName,
            token.arrayLength(),
            offset,
            token.encoding().primitiveType().size(),
            formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())));

        sb.append(String.format(
            indent + "    std::uint64_t get%1$s(char *dst, const std::uint64_t length) const\n" +
            indent + "    {\n" +
            indent + "        if (length > %2$d)\n" +
            indent + "        {\n" +
            indent + "             throw std::runtime_error(\"length too large for get%1$s [E106]\");\n" +
            indent + "        }\n\n" +
                "%3$s" +
            indent + "        std::memcpy(dst, m_buffer + m_offset + %4$d, length);\n" +
            indent + "        return length;\n" +
            indent + "    }\n\n",
            toUpperFirstChar(propertyName),
            token.arrayLength(),
            generateArrayFieldNotPresentCondition(token.version(), indent),
            offset));

        sb.append(String.format(
            indent + "    %1$s &put%2$s(const char *src)\n" +
            indent + "    {\n" +
            indent + "        std::memcpy(m_buffer + m_offset + %3$d, src, %4$d);\n" +
            indent + "        return *this;\n" +
            indent + "    }\n\n",
            containingClassName,
            toUpperFirstChar(propertyName),
            offset,
            token.arrayLength()));

        if (token.encoding().primitiveType() == PrimitiveType.CHAR)
        {
            sb.append(String.format(
                indent + "    std::string get%1$sAsString() const\n" +
                indent + "    {\n" +
                indent + "        std::string result(m_buffer + m_offset + %2$d, %3$d);\n" +
                indent + "        return result;\n" +
                indent + "    }\n\n",
                toUpperFirstChar(propertyName),
                offset,
                token.arrayLength()));

            sb.append(String.format(
                indent + "    %1$s &put%2$s(const std::string& str)\n" +
                indent + "    {\n" +
                indent + "        std::memcpy(m_buffer + m_offset + %3$d, str.c_str(), %4$d);\n" +
                indent + "        return *this;\n" +
                indent + "    }\n\n",
                containingClassName,
                toUpperFirstChar(propertyName),
                offset,
                token.arrayLength()));
        }

        return sb;
    }

    private CharSequence generateConstPropertyMethods(final String propertyName, final Token token, final String indent)
    {
        final String cppTypeName = cppTypeName(token.encoding().primitiveType());

        if (token.encoding().primitiveType() != PrimitiveType.CHAR)
        {
            return String.format(
                "\n" +
                indent + "static %1$s %2$s()\n" +
                indent + "{\n" +
                indent + "    return %3$s;\n" +
                indent + "}\n",
                cppTypeName,
                propertyName,
                generateLiteral(token.encoding().primitiveType(), token.encoding().constValue().toString()));
        }

        final StringBuilder sb = new StringBuilder();

        final byte[] constantValue = token.encoding().constValue().byteArrayValue(token.encoding().primitiveType());
        final StringBuilder values = new StringBuilder();
        for (final byte b : constantValue)
        {
            values.append(b).append(", ");
        }

        if (values.length() > 0)
        {
            values.setLength(values.length() - 2);
        }

        sb.append(String.format(
            "\n" +
            indent + "static uint64_t %1$sLength(void)\n" +
            indent + "{\n" +
            indent + "    return %2$d;\n" +
            indent + "}\n\n",
            propertyName,
            constantValue.length));

        sb.append(String.format(
            indent + "const char *%1$s(void) const\n" +
            indent + "{\n" +
            indent + "    static uint8_t %1$sValues[] = {%2$s};\n\n" +
            indent + "    return (const char *)%1$sValues;\n" +
            indent + "}\n\n",
            propertyName,
            values
        ));

        sb.append(String.format(
            indent + "%1$s %2$s(const std::uint64_t index) const\n" +
            indent + "{\n" +
            indent + "    static uint8_t %2$sValues[] = {%3$s};\n\n" +
            indent + "    return %2$sValues[index];\n" +
            indent + "}\n\n",
            cppTypeName,
            propertyName,
            values));

        sb.append(String.format(
            indent + "std::uint64_t get%1$s(char *dst, const std::uint64_t length) const\n" +
            indent + "{\n" +
            indent + "    static uint8_t %2$sValues[] = {%3$s};\n" +
            indent + "    std::uint64_t bytesToCopy = (length < sizeof(%2$sValues)) ? length : sizeof(%2$sValues);\n\n" +
            indent + "    std::memcpy(dst, %2$sValues, bytesToCopy);\n" +
            indent + "    return bytesToCopy;\n" +
            indent + "}\n",
            toUpperFirstChar(propertyName),
            propertyName,
            values));

        return sb;
    }

    private static CharSequence generateFixedFlyweightCode(final String className, final int size)
    {
        return String.format(
            "typedef struct sbe_%1$s_s {\n" +
            "    char *buffer;\n" +
            "    uint64_t bufferLength;\n" +
            "    uint64_t offset;\n" +
            "    uint64_t actingVersion;\n" +
            "} sbe_%1$s_t;\n\n" +
            "static int sbe_%1$s_reset(sbe_%1$s_t *message_header, char *buffer, const uint64_t offset, " +
                    "const uint64_t buffer_length, " +
            " const uint64_t acting_version)\n" +
            "{\n" +
            "    if (SBE_BOUNDS_CHECK_EXPECT(((offset + %2$s) > buffer_length), 0))\n" +
            "    {\n" +
            "        /* FIXME: error handling (buffer too short for flyweight [E107]) */\n" +
            "        return 1;\n" +
            "    }\n" +
            "    message_header->buffer = buffer;\n" +
            "    message_header->buffer_length = bufferLength;\n" +
            "    message_header->offset = offset;\n" +
            "    message_header->acting_version = acting_version;\n" +
            "    return 0;\n" +
            "}\n\n" +
            "static int sbe_%1$s_new(sbe_%1$s_t **message_header)\n" +
            "{\n" +
            "    *message_header = (sbe_%1$s_t*)malloc(sizeof(sbe_%1$s_t));\n" +
            "    return 0;\n" +
            "}\n\n" +
            "static int sbe_%1$s_free(sbe_%1$s_t **message_header)\n" +
            "{\n" +
            "    free(*message_header);\n" +
            "    *message_header = NULL;\n" +
            "    return 0;\n" +
            "}\n\n" +
            "static uint64_t sbe_%1$s_encoded_length()\n" +
            "{\n" +
            "    return %2$s;\n" +
            "}\n\n" +
            "uint64_t sbe_%1$s_offset(sbe_%1$s_t *message_header)\n" +
            "{\n" +
            "    return message_header->offset;\n" +
            "}\n\n" +
            "char *sbe_%1$s_buffer(sbe_%1$s_t *message_header)\n" +
            "{\n" +
            "    return message_header->buffer;\n" +
            "}\n\n",
            className,
            size);
    }

    private static CharSequence generateConstructorsAndOperators(final String className)
    {
        return String.format(
            "int sbe_%1$s_new(char *buffer, uint64_t buffer_length, sbe_%1$s_t **%1$s)\n" +
            "{\n" +
            "    %1$s->buffer = NULL;\n" +
            "    %1$s->buffer_length = 0;\n" +
            "    %1$s->offset = 0;\n" +
            "    sbe_%1$s_reset(%1$s, buffer, 0, buffer_length, sbe_block_length(), sbe_schema_version());\n" +
            "}\n" +
            "int sbe_%1$s_new(char *buffer, uint64_t buffer_length, uint64_t acting_block_length, " +
                    "uint64_t acting_version, sbe_%1$s_t **%1$s)\n" +
            "{\n" +
            "    %1$s->buffer = NULL;\n" +
            "    %1$s->buffer_length = 0;\n" +
            "    %1$s->offset = 0;\n" +
            "    sbe_%1$s_reset(%1$s, buffer, 0, buffer_length, acting_block_length, acting_version);\n" +
            "}\n\n",
            className);
    }

    private CharSequence generateMessageFlyweightCode(final String className, final Token token)
    {
        final String blockLengthType = cppTypeName(ir.headerStructure().blockLengthType());
        final String templateIdType = cppTypeName(ir.headerStructure().templateIdType());
        final String schemaIdType = cppTypeName(ir.headerStructure().schemaIdType());
        final String schemaVersionType = cppTypeName(ir.headerStructure().schemaVersionType());
        final String semanticType = token.encoding().semanticType() == null ? "" : token.encoding().semanticType();

        return String.format(
            "typedef struct sbe_%10$s_s {\n" +
            "    char *buffer;\n" +
            "    uint64_t buffer_length;\n" +
            "    uint64_t *position_ptr;\n" +
            "    uint64_t offset;\n" +
            "    uint64_t position;\n" +
            "    uint64_t acting_block_length;\n" +
            "    uint64_t acting_version;\n" +
            "} sbe_%10$s_t;\n\n" +
            "void sbe_%10$s_set_position(sbe_%10$s_t *%10$s, uint64_t position)\n" +
            "{\n" +
            "    if (SBE_BOUNDS_CHECK_EXPECT((position > %10$s->buffer_length), false))\n" +
            "    {\n" +
            "        /* FIXME: buffer too short [E100] */\n" +
            "        return 0;\n" +
            "    }\n" +
            "    %10$s->position = position;\n" +
            "}\n\n" +
            "static void sbe_%10$s_reset(\n" +
            "    sbe_%10$s_t *%10$s, char *buffer, uint64_t offset, uint64_t buffer_length,\n" +
            "    uint64_t acting_block_length, uint64_t acting_version)\n" +
            "{\n" +
            "    %10$s->buffer = buffer;\n" +
            "    %10$s->offset = offset;\n" +
            "    %10$s->buffer_length = buffer_length;\n" +
            "    %10$s->acting_block_length = acting_block_length;\n" +
            "    %10$s->acting_version = acting_version;\n" +
            "    %10$s->position_ptr = &%10$s->position;\n" +
            "    position(offset + %10$s->acting_block_length);\n" +
            "}\n\n" +
            "%11$s" +
            "static %1$s sbe_%10$s_block_length()\n" +
            "{\n" +
            "    return %2$s;\n" +
            "}\n\n" +
            "static const %3$s sbe_%10$s_template_id()\n" +
            "{\n" +
            "    return %4$s;\n" +
            "}\n\n" +
            "static const %5$s sbe_%10$s_schema_id()\n" +
            "{\n" +
            "    return %6$s;\n" +
            "}\n\n" +
            "static const %7$s sbe_%10$s_schema_version()\n" +
            "{\n" +
            "    return %8$s;\n" +
            "}\n\n" +
            "static const char * sbe_%10$s_semantic_type()\n" +
            "{\n" +
            "    return \"%9$s\";\n" +
            "}\n\n" +
            "uint64_t sbe_%10$s_offset()\n" +
            "{\n" +
            "    return m_offset;\n" +
            "}\n\n" +
            "%10$s &wrapForEncode(char *buffer, const std::uint64_t offset, const std::uint64_t bufferLength)\n" +
            "{\n" +
            "    reset(buffer, offset, bufferLength, sbeBlockLength(), sbeSchemaVersion());\n" +
            "    return *this;\n" +
            "}\n\n" +
            "%10$s &wrapForDecode(\n" +
            "     char *buffer, const std::uint64_t offset, const std::uint64_t actingBlockLength,\n" +
            "     const std::uint64_t actingVersion, const std::uint64_t bufferLength)\n" +
            "{\n" +
            "    reset(buffer, offset, bufferLength, actingBlockLength, actingVersion);\n" +
            "    return *this;\n" +
            "}\n\n" +
            "uint64_t sbe_%10$s_position(sbe_%10$s_t *%10$s)\n" +
            "{\n" +
            "    return %10$s->position;\n" +
            "}\n\n" +
            "uint64_t sbe_%10$s_encoded_length(sbe_%10$s_t *%10$s)\n" +
            "{\n" +
            "    return sbe_%10$s_position() - %10$s->offset;\n" +
            "}\n\n" +
            "char *sbe_%10$s_buffer(sbe_%10$s_t *%10$s)\n" +
            "{\n" +
            "    return %10$s->buffer;\n" +
            "}\n\n" +
            "uint64_t sbe_%10$s_acting_version(sbe_%10$s_t *%10$s)\n" +
            "{\n" +
            "    return %10$s->acting_version;\n" +
            "}\n",
            blockLengthType,
            generateLiteral(ir.headerStructure().blockLengthType(), Integer.toString(token.encodedLength())),
            templateIdType,
            generateLiteral(ir.headerStructure().templateIdType(), Integer.toString(token.id())),
            schemaIdType,
            generateLiteral(ir.headerStructure().schemaIdType(), Integer.toString(ir.id())),
            schemaVersionType,
            generateLiteral(ir.headerStructure().schemaVersionType(), Integer.toString(token.version())),
            semanticType,
            fromCamelCaseToUnderscore(className),
            generateConstructorsAndOperators(fromCamelCaseToUnderscore(className)));
    }

    private CharSequence generateFields(final String containingClassName, final List<Token> tokens, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        for (int i = 0, size = tokens.size(); i < size; i++)
        {
            final Token signalToken = tokens.get(i);
            if (signalToken.signal() == Signal.BEGIN_FIELD)
            {
                final Token encodingToken = tokens.get(i + 1);
                final String propertyName = fromCamelCaseToUnderscore(signalToken.name());
                final String className = fromCamelCaseToUnderscore(containingClassName);

                sb.append(String.format(
                    "\n" +
                    indent + "static uint16_t sbe_%3$s_%1$s_id()\n" +
                    indent + "{\n" +
                    indent + "    return %2$d;\n" +
                    indent + "}\n\n",
                    propertyName,
                    signalToken.id(),
                    className));

                sb.append(String.format(
                    indent + "static uint64_t sbe_%3$s_%1$s_since_version()\n" +
                    indent + "{\n" +
                    indent + "    return %2$d;\n" +
                    indent + "}\n\n" +
                    indent + "int sbe_%1$s_in_acting_version(sbe_%3$s_t *%3$s)\n" +
                    indent + "{\n" +
                    indent + "    return %3$s->acting_version >= sbe_%3$s_%1$s_since_version();\n" +
                    indent + "}\n\n",
                    propertyName,
                    (long)signalToken.version(),
                    className));

                generateFieldMetaAttributeMethod(sb, containingClassName, signalToken, indent);

                switch (encodingToken.signal())
                {
                    case ENCODING:
                        sb.append(generatePrimitiveProperty(containingClassName, propertyName, encodingToken, indent));
                        break;

                    case BEGIN_ENUM:
                        sb.append(generateEnumProperty(containingClassName, signalToken,
                                propertyName, encodingToken, indent));
                        break;

                    case BEGIN_SET:
                        sb.append(generateBitsetProperty(propertyName, encodingToken, indent));
                        break;

                    case BEGIN_COMPOSITE:
                        sb.append(generateCompositeProperty(propertyName, encodingToken, indent));
                        break;
                }
            }
        }

        return sb;
    }

    private static void generateFieldMetaAttributeMethod(final StringBuilder sb, final String className,
                                                         final Token token, final String indent)
    {
        final Encoding encoding = token.encoding();
        final String epoch = encoding.epoch() == null ? "" : encoding.epoch();
        final String timeUnit = encoding.timeUnit() == null ? "" : encoding.timeUnit();
        final String semanticType = encoding.semanticType() == null ? "" : encoding.semanticType();

        sb.append(String.format(
            "\n" +
            indent + "static const char *sbe_%5$s_%1s_meta_attribute(sbe_meta_attribute_t meta_attribute)\n" +
            indent + "{\n" +
            indent + "    switch (meta_attribute)\n" +
            indent + "    {\n" +
            indent + "        case META_ATTRIBUTE_EPOCH: return \"%s\";\n" +
            indent + "        case META_ATTRIBUTE_TIME_UNIT: return \"%s\";\n" +
            indent + "        case META_ATTRIBUTE_SEMANTIC_TYPE: return \"%s\";\n" +
            indent + "    }\n\n" +
            indent + "    return \"\";\n" +
            indent + "}\n",
            fromCamelCaseToUnderscore(token.name()),
            epoch,
            timeUnit,
            semanticType,
            fromCamelCaseToUnderscore(className)));
    }

    private static CharSequence generateEnumFieldNotPresentCondition(
        final int sinceVersion,
        final String enumName,
        final String indent)
    {
        if (0 == sinceVersion)
        {
            return "";
        }

        return String.format(
            indent + "        if (m_actingVersion < %1$d)\n" +
            indent + "        {\n" +
            indent + "            return %2$s::NULL_VALUE;\n" +
            indent + "        }\n\n",
            sinceVersion,
            enumName);
    }

    private CharSequence generateEnumProperty(
        final String containingClassName,
        final Token signalToken,
        final String propertyName,
        final Token token,
        final String indent)
    {
        final String enumName = formatStructName(token.name());
        final String typeName = cppTypeName(token.encoding().primitiveType());
        final int offset = token.offset();

        final StringBuilder sb = new StringBuilder();

        if (token.isConstantEncoding())
        {
            final String constValue = signalToken.encoding().constValue().toString();

            sb.append(String.format(
                "\n" +
                indent + "    %1$s::Value %2$s(void) const\n" +
                indent + "    {\n" +
                "%3$s" +
                indent + "        return %1$s::Value::%4$s;\n" +
                indent + "    }\n\n",
                enumName,
                propertyName,
                generateEnumFieldNotPresentCondition(token.version(), enumName, indent),
                constValue.substring(constValue.indexOf(".") + 1)));
        }
        else
        {
            sb.append(String.format(
                "\n" +
                indent + "    %1$s::Value %2$s(void) const\n" +
                indent + "    {\n" +
                "%3$s" +
                indent + "        return %1$s::get(%4$s(*((%5$s *)(m_buffer + m_offset + %6$d))));\n" +
                indent + "    }\n\n",
                enumName,
                propertyName,
                generateEnumFieldNotPresentCondition(token.version(), enumName, indent),
                formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType()),
                typeName,
                offset));

            sb.append(String.format(
                indent + "    %1$s &%2$s(const %3$s::Value value)\n" +
                indent + "    {\n" +
                indent + "        *((%4$s *)(m_buffer + m_offset + %5$d)) = %6$s(value);\n" +
                indent + "        return *this;\n" +
                indent + "    }\n",
                formatStructName(containingClassName),
                propertyName,
                enumName,
                typeName,
                offset,
                formatByteOrderEncoding(token.encoding().byteOrder(), token.encoding().primitiveType())));
        }

        return sb;
    }

    private static Object generateBitsetProperty(final String propertyName, final Token token, final String indent)
    {
        final StringBuilder sb = new StringBuilder();

        final String bitsetName = formatStructName(token.name());
        final int offset = token.offset();

        sb.append(String.format(
            "\n" +
            indent + "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            indent + "public:\n",
            bitsetName,
            propertyName));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s &%2$s()\n" +
            indent + "    {\n" +
            indent + "        m_%2$s.wrap(m_buffer, m_offset + %3$d, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            bitsetName,
            propertyName,
            offset));

        return sb;
    }

    private static Object generateCompositeProperty(final String propertyName, final Token token, final String indent)
    {
        final String compositeName = formatStructName(token.name());
        final int offset = token.offset();

        final StringBuilder sb = new StringBuilder();

        sb.append(String.format(
            "\n" +
            "private:\n" +
            indent + "    %1$s m_%2$s;\n\n" +
            "public:\n",
            compositeName,
            propertyName));

        sb.append(String.format(
            "\n" +
            indent + "    %1$s &%2$s(void)\n" +
            indent + "    {\n" +
            indent + "        m_%2$s.wrap(m_buffer, m_offset + %3$d, m_actingVersion, m_bufferLength);\n" +
            indent + "        return m_%2$s;\n" +
            indent + "    }\n",
            compositeName,
            propertyName,
            offset));

        return sb;
    }

    private CharSequence generateNullValueLiteral(final PrimitiveType primitiveType, final Encoding encoding)
    {
        // Visual C++ does not handle minimum integer values properly
        // See: http://msdn.microsoft.com/en-us/library/4kh09110.aspx
        // So some of the null values get special handling
        if (null == encoding.nullValue())
        {
            switch (primitiveType)
            {
                case CHAR:
                case FLOAT:
                case DOUBLE:
                    break; // no special handling
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

    private CharSequence generateLiteral(final PrimitiveType type, final String value)
    {
        String literal = "";

        final String castType = cppTypeName(type);
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
}
