/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
// SPDX-License-Identifier: GPL-3.0

#include <test/tools/ossfuzz/SolidityGenerator.h>

#include <libsolutil/Whiskers.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>

#include <algorithm>

using namespace solidity::test::fuzzer;
using namespace solidity::util;
using namespace std;
using MP = solidity::test::fuzzer::GenerationProbability;

const std::vector<std::string> FunctionDefinitionGenerator::s_visibility = {
	"public",
	"private",
	"external",
	"internal"
};

const vector<string> FunctionTypeGenerator::s_visibility = {
	"external",
	"internal"
};

const vector<string> FunctionDefinitionGenerator::s_mutability = {
	"payable",
	"view",
	"pure",
	"" // non payable
};

map<NatSpecGenerator::TagCategory, vector<NatSpecGenerator::Tag>> NatSpecGenerator::s_tagLookup = {
	{
		NatSpecGenerator::TagCategory::CONTRACT,
		{
			NatSpecGenerator::Tag::TITLE,
			NatSpecGenerator::Tag::AUTHOR,
			NatSpecGenerator::Tag::NOTICE,
			NatSpecGenerator::Tag::DEV,
		}
	},
	{
		NatSpecGenerator::TagCategory::FUNCTION,
		{
			NatSpecGenerator::Tag::NOTICE,
			NatSpecGenerator::Tag::DEV,
			NatSpecGenerator::Tag::PARAM,
			NatSpecGenerator::Tag::RETURN,
			NatSpecGenerator::Tag::INHERITDOC
		}
	},
	{
		NatSpecGenerator::TagCategory::PUBLICSTATEVAR,
		{
			NatSpecGenerator::Tag::NOTICE,
			NatSpecGenerator::Tag::DEV,
			NatSpecGenerator::Tag::RETURN,
			NatSpecGenerator::Tag::INHERITDOC
		}
	},
	{
		NatSpecGenerator::TagCategory::EVENT,
		{
			NatSpecGenerator::Tag::NOTICE,
			NatSpecGenerator::Tag::DEV,
			NatSpecGenerator::Tag::PARAM
		}
	}
};

const vector<string> FunctionDefinitionGenerator::s_freeFunctionMutability = {
	"view",
	"pure",
	"" // non payable
};

GeneratorBase::GeneratorBase(std::shared_ptr<SolidityGenerator> _mutator)
{
	mutator = std::move(_mutator);
	rand = mutator->randomEngine();
	state = mutator->testState();
}


string GenerationProbability::generateRandomAsciiString(size_t _length, std::shared_ptr<RandomEngine> _rand)
{
	vector<char> s{};
	for (size_t i = 0; i < _length * 2; i++)
		s.push_back(
			static_cast<char>(Distribution(0x21, 0x7e)(*_rand))
		);
	return string(s.begin(), s.end());
}

string GenerationProbability::generateRandomHexString(size_t _length, std::shared_ptr<RandomEngine> _rand)
{
	static char const* hexDigit = "0123456789abcdefABCDEF_";
	vector<char> s{};
	for (size_t i = 0; i < _length * 2; i++)
		s.push_back(hexDigit[distributionOneToN(23, _rand) - 1]);
	return string(s.begin(), s.end());
}

pair<GenerationProbability::NumberLiteral, string> GenerationProbability::generateRandomNumberLiteral(
	size_t _length,
	std::shared_ptr<RandomEngine> _rand
)
{
	static char const* hexDigit = "0123456789abcdefABCDEF_";
	static char const* decimalDigit = "0123456789_eE-.";
	vector<char> s{};
	NumberLiteral n;
	if (chooseOneOfN(2, _rand))
	{
		n = NumberLiteral::HEX;
		for (size_t i = 0; i < _length * 2; i++)
			s.push_back(hexDigit[distributionOneToN(23, _rand) - 1]);
	}
	else
	{
		n = NumberLiteral::DECIMAL;
		for (size_t i = 0; i < _length * 2; i++)
			s.push_back(decimalDigit[distributionOneToN(15, _rand) - 1]);
	}
	return pair(n, string(s.begin(), s.end()));
}

string ExportedSymbols::randomSymbol(shared_ptr<RandomEngine> _rand)
{
	auto it = symbols.begin();
	auto idx = (*_rand)() % symbols.size();
	for (size_t i = 0; i < idx; i++)
		it++;
	return *it;
}

string ExportedSymbols::randomUserDefinedType(shared_ptr<RandomEngine> _rand)
{
	auto it = types.begin();
	auto idx = (*_rand)() % types.size();
	for (size_t i = 0; i < idx; i++)
		it++;
	return *it;
}

bool FunctionState::operator==(const FunctionState& _other)
{
	if (_other.inputParameters.size() != inputParameters.size())
		return false;
	else
	{
		unsigned index = 0;
		for (auto const& type: _other.inputParameters)
			if (type.first.type != inputParameters[index++].first.type)
				return false;
		return name == _other.name;
	}
}

string TestState::randomPath()
{
	solAssert(!empty(), "Solc custom mutator: Null test state");
	for (auto iter = sourceUnitStates.begin(); iter != sourceUnitStates.end(); )
	{
		// Choose this element equally at random
		if (MP{}.chooseOneOfN(sourceUnitStates.size(), rand))
			return iter->first;
		// If not chosen, increment iterator checking if this
		// is the last element. If it is not the last element
		// continue, otherwise choose it.
		else if (++iter == sourceUnitStates.end())
			return (--iter)->first;
	}
	solAssert(false, "Solc custom mutator: No source path chosen");
}

GeneratorPtr GeneratorBase::randomGenerator()
{
	solAssert(generators.size() > 0, "Invalid hierarchy");

	auto it = generators.begin();
	auto idx = (*rand)() % generators.size();
	for (size_t i = 0; i < idx; i++)
		it++;
	return *it;
}

string GeneratorBase::visitChildren()
{
	ostringstream os;
	// Randomise visit order
	vector<GeneratorPtr> randomisedChildren;
	for (auto child: generators)
		randomisedChildren.push_back(child);
	shuffle(randomisedChildren.begin(), randomisedChildren.end(), *rand);
	std::cout << "Visiting children" << std::endl;
	for (auto child: randomisedChildren)
	{
		std::cout << "Visiting " << std::visit(NameVisitor{}, child) << std::endl;
		os << std::visit(GeneratorVisitor{}, child);
	}

	return os.str();
}

void TestCaseGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<SourceUnitGenerator>()
		}
	);
}

string TestCaseGenerator::visit()
{
	ostringstream os;
	for (unsigned i = 0; i < MP{}.distributionOneToN(s_maxSourceUnits, rand); i++)
	{
		string sourcePath = path();
		os << Whiskers(m_sourceUnitHeader)
			("path", sourcePath)
			.render();
		addSourceUnit(sourcePath);
		m_numSourceUnits++;
		os << visitChildren();
		generator<SourceUnitGenerator>()->reset();
	}
	return os.str();
}

string TestCaseGenerator::randomPath()
{
	solAssert(!empty(), "Solc custom mutator: Invalid source unit");
	return path(MP{}.distributionOneToN(m_numSourceUnits, rand) - 1);
}

string ExpressionGenerator::doubleQuotedStringLiteral()
{
	string s = MP{}.generateRandomAsciiString(
		MP{}.distributionOneToN(s_maxStringLength, rand),
		rand
	);
	return Whiskers(R"("<string>")")
		("string", s)
		.render();
}

string ExpressionGenerator::hexLiteral()
{
	string s = MP{}.generateRandomHexString(
		MP{}.distributionOneToN(s_maxHexLiteralLength, rand),
		rand
	);
	return Whiskers(R"(hex"<string>")")
		("string", s)
		.render();
}

string ExpressionGenerator::numberLiteral()
{
	auto [n, s] = MP{}.generateRandomNumberLiteral(
		MP{}.distributionOneToN(s_maxHexLiteralLength, rand),
		rand
	);
	if (n == MP::NumberLiteral::HEX)
		return "hex\"" + s + "\"";
	else
		return s;
}

string ExpressionGenerator::addressLiteral()
{
	return Whiskers(R"(0x<string>)")
		("string", MP{}.generateRandomHexString(20, rand))
		.render();
}

string ExpressionGenerator::literal()
{
	switch (MP{}.distributionOneToN(5, rand))
	{
	case 1:
		return doubleQuotedStringLiteral();
	case 2:
		return hexLiteral();
	case 3:
		return numberLiteral();
	case 4:
		return boolLiteral();
	case 5:
		return addressLiteral();
	}
	solAssert(false, "");
}

string ExpressionGenerator::expression()
{
	if (nestingDepthTooHigh())
		return literal();

	incrementNestingDepth();

	string expr;
	switch (MP{}.distributionOneToN(Type::TYPEMAX, rand) - 1)
	{
	case Type::INDEXACCESS:
		expr = Whiskers(R"(<baseExpr>[<indexExpr>])")
			("baseExpr", expression())
			("indexExpr", expression())
			.render();
		break;
	case Type::INDEXRANGEACCESS:
		expr = Whiskers(R"(<baseExpr>[<startExpr>:<endExpr>])")
			("baseExpr", expression())
			("startExpr", expression())
			("endExpr", expression())
			.render();
		break;
	case Type::METATYPE:
		expr = Whiskers(R"(type(<typeName>))")
			("typeName", generator<TypeGenerator>()->visit())
			.render();
		break;
	case Type::BITANDOP:
		expr = Whiskers(R"(<left> & <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::BITOROP:
		expr = Whiskers(R"(<left> | <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::BITXOROP:
		expr = Whiskers(R"(<left> ^ <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::ANDOP:
		expr = Whiskers(R"(<left> && <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::OROP:
		expr = Whiskers(R"(<left> || <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::NEWEXPRESSION:
		expr = Whiskers(R"(new <typeName>)")
			("typeName", generator<TypeGenerator>()->visit())
			.render();
		break;
	case Type::CONDITIONAL:
		expr = Whiskers(R"(<conditional> ? <trueExpression> : <falseExpression)")
			("conditional", expression())
			("trueExpression", expression())
			("falseExpression", expression())
			.render();
		break;
	case Type::ASSIGNMENT:
		expr = Whiskers(R"(<left> = <right>)")
			("left", expression())
			("right", expression())
			.render();
		break;
	case Type::INLINEARRAY:
	{
		vector<string> exprs{};
		size_t numElementsInTuple = MP{}.distributionOneToN(s_maxElementsInlineArray, rand);
		for (size_t i = 0; i < numElementsInTuple; i++)
			exprs.push_back(expression());
		expr = Whiskers(R"([<inlineArrayExpression>])")
			("inlineArrayExpression", boost::algorithm::join(exprs, ", "))
			.render();
		break;
	}
	case Type::IDENTIFIER:
		if (state->currentSourceState().symbols())
			expr = state->currentSourceState().exportedSymbols.randomSymbol(rand);
		else
			expr = literal();
		break;
	case Type::LITERAL:
		expr = literal();
		break;
	case Type::TUPLE:
	{
		vector<string> exprs{};
		size_t numElementsInTuple = MP{}.distributionOneToN(s_maxElementsInTuple, rand);
		for (size_t i = 0; i < numElementsInTuple; i++)
			exprs.push_back(expression());
		expr = Whiskers(R"((<tupleExpression>))")
			("tupleExpression", boost::algorithm::join(exprs, ", "))
			.render();
		break;
	}
	default:
		expr = literal();
	}
	return typeString() + "(" + expr + ")";
}

void ExpressionGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<TypeGenerator>()
		}
	);
}

string ExpressionGenerator::visit()
{
	string expr{};
	if (m_compileTimeConstantExpressionsOnly)
		// TODO: Reference identifiers that point to
		// compile time constant expressions.
		return literal();
	else
		return expression();
}

string StateVariableDeclarationGenerator::visibility()
{
	switch (MP{}.distributionOneToN(Visibility::VISIBILITYMAX, rand) - 1)
	{
	case Visibility::INTERNAL:
		return "internal";
	case Visibility::PRIVATE:
		return "private";
	case Visibility::PUBLIC:
		return "public";
	default:
		solAssert(false, "");
	}
}

void StateVariableDeclarationGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<ExpressionGenerator>(),
			mutator->generator<NatSpecGenerator>()
		}
	);
}

string StateVariableDeclarationGenerator::visit()
{
	string id = identifier();
    string type = generator<ExpressionGenerator>()->typeString();
	string vis = visibility();
	bool immutable = false;
	bool constant = MP{}.chooseOneOfN(2, rand);
	if (!constant)
		immutable = MP{}.chooseOneOfN(2, rand);
	solAssert(!(constant && immutable), "State variable cannot be both constant and immutable");
	string expr = generator<ExpressionGenerator>()->visit();
	// TODO: Actually restrict this setting to public state variables only
	generator<NatSpecGenerator>()->tagCategory(NatSpecGenerator::TagCategory::PUBLICSTATEVAR);
	string natSpecString = generator<NatSpecGenerator>()->visit();
	return Whiskers(m_declarationTemplate)
		("natSpecString", natSpecString)
		("type", type)
		("vis", vis)
		("constant", constant)
		("immutable", immutable)
		("id", id)
		("value", expr)
		.render();
}

/*
string IntegerType::visit()
{
	if (sign)
		return "int" + width.visit();
	else
		return "uint" + width.visit();
}
 */

string IntegerTypeGenerator::visit()
{
	//bool sign = MP{}.chooseOneOfN(2, rand);
	//unsigned width = static_cast<unsigned>((*rand)());
	//return IntegerType(sign, width).visit();
	return "uint";
}

void UserDefinedTypeGenerator::setup()
{
	addGenerators({mutator->generator<FunctionTypeGenerator>()});
}

string UserDefinedTypeGenerator::visit()
{
	switch (MP{}.distributionOneToN(2, rand))
	{
	case 1:
		if (state->currentSourceState().userDefinedTypes())
			return state->currentSourceState().exportedSymbols.randomUserDefinedType(rand);
		else
			return "uint";
	case 2:
		return generator<FunctionTypeGenerator>()->visit();
	}
	solAssert(false, "");
}

void BytesTypeGenerator::setup()
{
	addGenerators({mutator->generator<TypeGenerator>()});
}

string BytesTypeGenerator::visit()
{
	bool isBytes = MP{}.chooseOneOfN(33, rand);
	if (isBytes)
		generator<TypeGenerator>()->setNonValueType();
	return Whiskers(R"(bytes<?width><w></width>)")
		("width", !isBytes)
		("w", to_string(MP{}.distributionOneToN(32, rand)))
		.render();
}

string BoolTypeGenerator::visit()
{
	return "bool";
}

string AddressTypeGenerator::visit()
{
	return MP{}.chooseOneOfN(2, rand) ? "address" : "address payable";
}

void TypeGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<IntegerTypeGenerator>(),
			mutator->generator<UserDefinedTypeGenerator>(),
			mutator->generator<ArrayTypeGenerator>(),
			mutator->generator<BytesTypeGenerator>(),
			mutator->generator<BoolTypeGenerator>(),
			mutator->generator<AddressTypeGenerator>()
		}
	);
}

string TypeGenerator::visitNonArrayType()
{
	vector<GeneratorPtr> g;
	for (auto &gen: generators)
		if (!holds_alternative<shared_ptr<ArrayTypeGenerator>>(gen))
			g.push_back(gen);
	return std::visit(
		GeneratorVisitor{},
		g[MP{}.distributionOneToN(g.size(), rand) - 1]
	);
}

string TypeGenerator::visit()
{
	return std::visit(GeneratorVisitor{}, randomGenerator());
}

void ArrayTypeGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<TypeGenerator>()
		}
	);
}

string ArrayTypeGenerator::visit()
{
	if (m_numDimensions > s_maxArrayDimensions)
		return generator<TypeGenerator>()->visitNonArrayType();
	else
	{
		m_numDimensions++;
		return Whiskers(R"(<baseType>[<?static><size></static>])")
			("baseType", generator<TypeGenerator>()->visit())
			("static", MP{}.chooseOneOfN(2, rand))
			("size", to_string(MP{}.distributionOneToN(s_maxStaticArraySize, rand)))
			.render();
	}
}

string Location::visit()
{
	switch (loc)
	{
	case Location::Loc::CALLDATA:
		return "calldata";
	case Location::Loc::MEMORY:
		return "memory";
	case Location::Loc::STORAGE:
		return "storage";
	case Location::Loc::STACK:
		return "";
	}
}

string LocationGenerator::visit()
{
	switch (MP{}.distributionOneToN(4, rand))
	{
	case 1:
		return Location(Location::Loc::MEMORY).visit();
	case 2:
		return Location(Location::Loc::STORAGE).visit();
	case 3:
		return Location(Location::Loc::CALLDATA).visit();
	case 4:
		return Location(Location::Loc::STACK).visit();
	}
	solAssert(false, "");
}

string SimpleVariableDeclaration::visit()
{
	return Whiskers(simpleVarDeclTemplate)
		("type", "uint"/*type->visit()*/)
		("location", location.visit())
		("name", identifier)
		("assign", expression.has_value())
		("expression", expression.value()->visit())
		.render();
}

string ExpressionStatement::visit()
{
	// TODO: Implement expression generation
	return Whiskers(exprStmtTemplate)("expression", "1").render();
}

string BlockStatement::visit()
{
	ostringstream os;
	for (auto &stmt: statements)
		os << std::visit(GeneratorTypeVisitor{}, stmt);
	return os.str();
}

string VariableDeclaration::visit()
{
	return Whiskers(varDeclTemplate)
		("type", "uint"/*type->visit()*/)
		("location", location.visit())
		("name", identifier)
		.render();
}

string VariableDeclarationGenerator::identifier()
{
	string id = "v" + to_string(MP{}.distributionOneToN(10, rand));
	return id;
}

void VariableDeclarationGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<LocationGenerator>(),
			mutator->generator<TypeGenerator>()
		}
	);
}

string VariableDeclarationGenerator::visit()
{
	string type = generator<TypeGenerator>()->visit();
	bool nonValueType = dynamic_pointer_cast<TypeGenerator>(generator<TypeGenerator>())->nonValueType();
	string location = nonValueType ? generator<LocationGenerator>()->visit() : "";
	return Whiskers(R"(<type> <location> <id>)")
		("type", type)
		("location", location)
		("id", identifier())
		.render();
}

void ParameterListGenerator::setup()
{
	addGenerators({mutator->generator<VariableDeclarationGenerator>()});
}

string ParameterListGenerator::visit()
{
	size_t numParameters = MP{}.distributionOneToN(4, rand);
	ostringstream out;
	string sep{};
	for (size_t i = 0; i < numParameters; i++)
	{
		out << sep << generator<VariableDeclarationGenerator>()->visit();
		if (sep.empty())
			sep = ", ";
	}
	return out.str();
}

string FunctionDefinitionGenerator::functionIdentifier()
{
	switch (MP{}.distributionOneToN(3, rand))
	{
	case 1:
		return "f" + to_string(MP{}.distributionOneToN(10, rand));
	case 2:
		return "fallback";
	case 3:
		return "receive";
	}
	solAssert(false, "Invalid function identifier");
}

void FunctionDefinitionGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<ParameterListGenerator>(),
			mutator->generator<TypeGenerator>(),
			mutator->generator<NatSpecGenerator>()
		}
	);
}

string FunctionDefinitionGenerator::visit()
{
	string identifier = functionIdentifier();
	if (!state->currentSourceState().exportedSymbols.symbols.count(identifier))
		state->currentSourceState().exportedSymbols.symbols.insert(identifier);
	else
		return "";
	m_functionState->setName(identifier);
	string modInvocation = "";
	string virtualise = m_freeFunction ? "" : MP{}.chooseOneOfNStrings({"virtual", ""}, rand);
	string override = "";
	string visibility = m_freeFunction ? "" : MP{}.chooseOneOfNStrings(s_visibility, rand);
	string mutability = m_freeFunction ?
		MP{}.chooseOneOfNStrings(s_freeFunctionMutability, rand) :
		MP{}.chooseOneOfNStrings(s_mutability, rand);

	size_t numReturns = MP{}.distributionOneToN(4, rand) - 1;
	string sep{};
	string returns{};
	for (size_t i = 0; i < numReturns; i++)
	{
		returns += sep + generator<TypeGenerator>()->visit();
		if (sep.empty())
			sep = ", ";
	}

	generator<NatSpecGenerator>()->tagCategory(NatSpecGenerator::TagCategory::FUNCTION);
	string natSpecString = generator<NatSpecGenerator>()->visit();
	return Whiskers(m_functionTemplate)
		("natSpecString", natSpecString)
		("id", identifier)
		("paramList", generator<ParameterListGenerator>()->visit())
		("visibility", visibility)
		("stateMutability", mutability)
		("modInvocation", modInvocation)
		("virtual", virtualise)
		("overrideSpec", override)
		("return", !returns.empty())
		("retParamList", returns)
		("definition", true)
		("body", "{}")
		.render();
}

string EnumDeclaration::visit()
{
	string name = enumName();
	if (!state->currentSourceState().exportedSymbols.types.count(name))
		state->currentSourceState().exportedSymbols.types.insert(name);
	else
		return "";

	string members{};
	string sep{};
	for (size_t i = 0; i < MP{}.distributionOneToN(s_maxMembers, rand); i++)
	{
		members += sep + "M" + to_string(i);
		if (sep.empty())
			sep = ", ";
	}
	return Whiskers(enumTemplate)
		("name", name)
		("members", members)
		.render();
}

void FunctionTypeGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<TypeGenerator>()
		}
	);
}

string FunctionTypeGenerator::visit()
{
	string visibility = MP{}.chooseOneOfNStrings(s_visibility, rand);
	size_t numParams = MP{}.distributionOneToN(4, rand) - 1;
	size_t numReturns = MP{}.distributionOneToN(4, rand) - 1;
	string sep{};
	string params{};
	for (size_t i = 0; i < numParams; i++)
	{
		params += sep + generator<TypeGenerator>()->visit();
		if (sep.empty())
			sep = ", ";
	}
	sep = {};
	string returns{};
	for (size_t i = 0; i < numReturns; i++)
	{
		returns += sep + generator<TypeGenerator>()->visit();
		if (sep.empty())
			sep = ", ";
	}
	return Whiskers(m_functionTypeTemplate)
		("paramList", params)
		("visibility", visibility)
		("stateMutability", MP{}.chooseOneOfNStrings(FunctionDefinitionGenerator::s_mutability, rand))
		("return", !returns.empty())
		("retParamList", returns)
		.render();
}

void ConstantVariableDeclaration::setup()
{
	addGenerators(
		{
			mutator->generator<ExpressionGenerator>()
		}
	);
}

string ConstantVariableDeclaration::visit()
{
	// TODO: Set compileTimeConstantExpressionsOnly in
	// ExpressionGenerator to true
	return Whiskers(constantVarDeclTemplate)
		("type", generator<ExpressionGenerator>()->typeString())
		("name", "c")
		("expression", generator<ExpressionGenerator>()->visit())
		.render();
}

void SourceUnitGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<PragmaGenerator>(),
			mutator->generator<ImportGenerator>(),
			mutator->generator<ConstantVariableDeclaration>(),
			mutator->generator<EnumDeclaration>(),
			mutator->generator<FunctionDefinitionGenerator>(),
			mutator->generator<ContractDefinitionGenerator>()
		}
	);
}

string SourceUnitGenerator::visit()
{
	string sourceUnit = visitChildren();
	reset();
	return sourceUnit;
}

void SourceUnitGenerator::reset()
{
	for (auto &g: generators)
		std::visit(ResetVisitor{}, g);
}

string PragmaGenerator::generateExperimentalPragma()
{
	return "experimental ABIEncoderV2";
//	return string("experimental ") + (MP{}.chooseOneOfN(2, rand) ? "SMTChecker" : "ABIEncoderV2");
}

string PragmaGenerator::visit()
{
	return Whiskers(m_pragmaTemplate)
		("version", "solidity >= 0.0.0")
		("experimental", generateExperimentalPragma())
		.render();
}

void ContractDefinitionGenerator::setup()
{
	addGenerators(
		{
			mutator->generator<StateVariableDeclarationGenerator>(),
			mutator->generator<FunctionDefinitionGenerator>(),
			mutator->generator<NatSpecGenerator>()
		}
	);
}

string ContractDefinitionGenerator::visit()
{
	string stateVar = generator<StateVariableDeclarationGenerator>()->visit();
	string func = generator<FunctionDefinitionGenerator>()->visit();
	generator<NatSpecGenerator>()->tagCategory(NatSpecGenerator::TagCategory::CONTRACT);
	string natSpecString = generator<NatSpecGenerator>()->visit();
	return Whiskers(m_contractTemplate)
		("natSpecString", natSpecString)
		("abstract", MP{}.chooseOneOfN(s_abstractInvProb, rand))
		("id", "Cx")
		("inheritance", MP{}.chooseOneOfN(s_inheritanceInvProb, rand))
		("inheritanceSpecifierList", "X")
		("stateVar", stateVar)
		("function", func)
		.render();
}

void TestState::print()
{
	std::cout << "Printing test state" << std::endl;
	for (auto const& item: sourceUnitStates)
		std::cout << "Path: " << item.first << std::endl;
}

string TestState::randomNonCurrentPath()
{
	solAssert(size() >= 2, "Solc custom mutator: Invalid test state");
	string fallBackPath{};
	for (auto const& item: sourceUnitStates)
	{
		string iterPath = item.first;
		if (iterPath != currentSourceName)
		{
			// Fallback to first encountered non current path
			fallBackPath = iterPath;
			if (MP{}.chooseOneOfN(size() - 1, rand))
				return iterPath;
		}
	}
	return fallBackPath;
}

string ImportGenerator::visit()
{
	state->print();
	/*
	 * Case 1: No source units defined
	 * Case 2: One source unit defined
	 * Case 3: At least two source units defined
	 */
	// No import
	if (state->empty())
		return {};
	// Self import with a small probability
	else if (state->size() == 1)
	{
		if (MP{}.chooseOneOfN(s_selfImportInvProb, rand))
			return Whiskers(m_importPathAs)
				("path", state->randomPath())
				("as", false)
				.render();
		else
			return {};
	}
	// Import pseudo randomly choosen source unit
	else
	{
		string importPath = state->randomNonCurrentPath();
		auto importedSymbols = state->sourceUnitStates[importPath].exportedSymbols.symbols;
		state->currentSourceState().exportedSymbols.symbols.insert(
			importedSymbols.begin(),
			importedSymbols.end()
		);
		return Whiskers(m_importPathAs)
			("path", importPath)
			("as", false)
			.render();
	}
}

NatSpecGenerator::Tag NatSpecGenerator::randomTag(TagCategory _category)
{
	return s_tagLookup[_category][MP{}.distributionOneToN(s_tagLookup[_category].size(), rand) - 1];
}

string NatSpecGenerator::randomNatSpecString(TagCategory _category)
{
	if (m_nestingDepth > s_maxNestedTags)
		return {};
	else
	{
		m_nestingDepth++;
		string tag{};
		switch (randomTag(_category))
		{
		case Tag::TITLE:
			tag = "@title";
			break;
		case Tag::AUTHOR:
			tag = "@author";
			break;
		case Tag::NOTICE:
			tag = "@notice";
			break;
		case Tag::DEV:
			tag = "@dev";
			break;
		case Tag::PARAM:
			tag = "@param";
			break;
		case Tag::RETURN:
			tag = "@return";
			break;
		case Tag::INHERITDOC:
			tag = "@inheritdoc";
			break;
		}
		return Whiskers(m_tagTemplate)
			("tag", tag)
			("random", MP{}.generateRandomAsciiString(s_maxTextLength, rand))
			("recurse", randomNatSpecString(_category))
			.render();
	}
}

string NatSpecGenerator::visit()
{
	reset();
	return Whiskers(R"(<nl>/// <natSpecString><nl>)")
		("natSpecString", randomNatSpecString(m_tag))
		("nl", "\n")
		.render();
}

template <typename T>
shared_ptr<T> SolidityGenerator::generator()
{
	for (auto &g: m_generators)
		if (holds_alternative<shared_ptr<T>>(g))
			return get<shared_ptr<T>>(g);
	solAssert(false, "");
}

SolidityGenerator::SolidityGenerator(unsigned int _seed)
{
	m_rand = make_shared<RandomEngine>(_seed);
	m_generators = {};
	m_state = make_shared<TestState>(m_rand);
}

template <size_t I>
void SolidityGenerator::createGenerators()
{
	if constexpr (I < std::variant_size_v<Generator>)
	{
		createGenerator<std::variant_alternative_t<I, Generator>>();
		createGenerators<I + 1>();
	}
}

string SolidityGenerator::generateTestProgram()
{
	createGenerators();
	for (auto &g: m_generators)
		std::visit(AddDependenciesVisitor{}, g);
	return generator<TestCaseGenerator>()->visit();
}
