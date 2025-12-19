% 822387 Biondi Simone

looks_like_list([]).
looks_like_list([_|_]).
valid_escape_char('"',  '"').
valid_escape_char("'",  "'").

valid_escape_char('\'',  '\'').

json_parse(JSON, Object) :-
    findall(Object, json_space(JSON, Object), [Object|_]).

is_member([ ],_).
is_member([H|T],List) :-
    member(H,List),
    is_member(T,List).

% Leggi un file di testo
% Se contiene formato json ritorna true
json_load(FileName, JSON):-
    open(FileName, read, In),   % apro file
    % leggo contenuto file in una variabile (lista codici)
    read_file_to_codes(FileName, What, []), 
    close(In),
    % converto lista codici in singola stringa e la passo al parser
    string_codes(String, What),   
    json_parse(String, JSON).

% Scrivo un oggetto in formato json in un file
json_write(JSON, FileName) :-
    parse_object_to_json(JSON, Output),   % Converto oggetto in formato json
    open(FileName,write,Stream),
    write(Stream,Output),   % Scrittura su file...
    close(Stream).

json_space(JSON, Value) :-
    del_tab(JSON, JSON_NT),
    del_newline(JSON_NT, JSON_NL),
    atom_chars(JSON_NL, String),   % converto JSON_NL in una lista di caratteri
    phrase((json(Value)), String). % DCG, verifico la validità del formato json

% elimino spazi bianchi prima e dopo la punteggiatura simbolio di json
space -->
    space_char,
    !,
    space.
space --> [].

space_char -->
    [Char],
    {char_type(Char, space)}.

% funzione che restituisce la stringa in input senza caratteri 'tab'
del_tab(S, NoSpaces) :-
   atom_codes(S, Cs), delete(Cs, 9 , X), atom_codes(NoSpaces, X).

% restituisce la stringa in input senza caratteri 'new line'
del_newline(S, NoLine) :-
   atom_codes(S, Cs), delete(Cs, 10 , X), atom_codes(NoLine, X).

del_quote(S, A) :-
   term_to_atom(S,Ss),
   atom_codes(Ss, Cs), 
   delete(Cs, 91, Xx), 
   delete(Xx, 93, Xs), 
   atom_codes(NoSpaces, Xs),
   term_to_atom(Aa,NoSpaces),
   atom_string(Aa,A).
% delete(Cs, 34 , X),

del_quotes(S, A) :-
   term_to_atom(S,Ss),
   atom_codes(Ss, Cs), delete(Cs, 34 , X), atom_codes(NoSpaces, X),
   term_to_atom(Aa,NoSpaces),
   atom_string(Aa,A).
% essendo json composto da oggetto o array...
json(VAL) -->
    object(VAL);
    array(VAL).

object(O) -->
    (empty_object(O);
    full_object(O)).

array(A) -->
    empty_array(A);
    full_array(A).

empty_object(json_obj([])) -->
    space,
    ['{'],
    space,
    ['}'],
    space.             % oggetto vuoto

full_object(json_obj(O)) -->
    space,
    ['{'],
    members(O),
    space,        % scomposizione oggetto
    ['}'],
    space.

members([O]) -->
    pair(O).

% più membri di un oggetto...
members([O|Os]) -->
    pair(O),
    space,[','],space,
    members(Os).

% membro=Key:Value
% Key valore alfanumerico(stringa)
% Value può essere stringa,numero o json
pair(K','V) -->
    space,
    is_key(K),
    space,
    [':'],
    space,
    is_val(V),
    space.

is_key(K) -->
   is_string(K).

is_val(V) -->
    (is_string(V);
    json(V);
    parse_number(V)).

is_string(S) -->
    ['"'],
    parse_chars(S),
    ['"'].

is_string(S) -->
    ['\''],
    parse_chars(S),
    ['\''].

% Array vuoto
empty_array(json_array([])) -->
    space,
    ['['],
    space,
    [']'],
    space.

% Array contiene elementi...
full_array(json_array(A)) -->
    space,
    ['['],
    space,
    is_element(A),
    space,
    [']'],
    space.

% Uno o più elementi
% Elem può essere stringa,numero o json
is_element([E]) -->
    is_val(E).

is_element([E|Es]) -->
    space,
    is_val(E),
    space,
    [','],
    space,
    is_element(Es).

% Verifico la presenza di uno o più caratteri
% il carattere viene parsato all'oggetto se diverso da '"' o '\'
parse_chars(X) -->
    parser_chars(Chars),
    {atom_chars(Atom, Chars),atom_string(Atom,X) }.

parser_chars([Char|Chars]) -->
    ['\\'],
    !,
    parse_escape_sequence(Char),
    parser_chars(Chars).

parser_chars([Char|Chars]) -->
    parse_char(Char),
    parser_chars(Chars).

% Raggruppamento oggetto fra [ ]
parser_chars([]) --> [].

parse_escape_sequence(RealChar) -->
    [Char],
    { valid_escape_char(Char, RealChar) },
    !.

% Verifico che non ci sia il carattere '"'
parse_char(Char) -->
    [Char],
    {(Char \== '"')}.

% Verifico se elemento(e valore di membro) è un numero
% Può essere intero(negativo o positivo) o decimale(float)
parse_number(Number) -->
    parse_float(Number),
    !.

parse_number(Number) -->
    parse_integer(Number).

% Numero è float...
parse_float(Float) -->
    parse_optional_minus(Chars, Chars1),   % negativo
    parse_digits_for_integer(Chars1, ['.'|Chars0]), % parte intera
    ['.'],
    parse_float_or_throw(Chars0),   % parte decimale
    {number_chars(Float, Chars) }.

parse_float_or_throw(Chars) -->
    parse_digits(Chars, Chars0),
    parse_optional_exponent(Chars0),
    !.

% FLOAT NOTATION
parse_optional_exponent(Chars) -->
    parse_e(Chars, Chars1),
    parse_optional_sign(Chars1, Chars0),
    parse_digits(Chars0, []),
    !.
parse_optional_exponent([]) --> [].

parse_e(['e'|T], T) --> ['e'], !.
parse_e(['E'|T], T) --> ['E'], !.

parse_optional_sign(['+'|T], T) --> ['+'], !.
parse_optional_sign(['-'|T], T) --> ['-'], !.
parse_optional_sign(T, T)       --> [], !.

% Numero è intero
parse_integer(Integer) -->
    parse_optional_minus(Chars, Chars1),
    parse_digits_for_integer(Chars1, []),
    {number_chars(Integer, Chars) }.

parse_optional_minus(['-'|T], T) --> ['-'], !.
parse_optional_minus(T, T)       --> [], !.

parse_digits_for_integer([Digit|Digits], Digits0) -->
    parse_digit_nonzero(Digit),
    !,
    parse_optional_digits(Digits, Digits0).

parse_digits_for_integer([Digit|T], T) -->
    parse_digit(Digit).

parse_digit_nonzero(Digit) -->
    parse_digit(Digit),
    { Digit \== '0' }.

parse_optional_digits([Digit|Digits], T) -->
    parse_digit(Digit),
    !,
    parse_optional_digits(Digits, T).

parse_optional_digits(T, T) --> [].

parse_digits([Digit|Digits], T) -->
    parse_digit(Digit),
    parse_optional_digits(Digits, T).

parse_digit(Digit) -->
    [Digit],
    {char_type(Digit, digit) }.

% per la funzione write devo convertire oggetto in formato json
% Le DCG partono dall'oggetto intero fino a scomporlo

parse_object_to_json(Obj, Json) :-
    phrase(parse_json(Obj), String),
    atom_chars(Json, String).

parse_json(Obj) -->
    parse_object(Obj);
    parse_array(Obj).
parse_object(json_obj([])) -->  % oggetto vuoto
    !,
    ['{'],
    ['}'].

parse_object(json_obj(O)) -->
    ['{'],
    parse_members(O),
    ['}'].

parse_members([M]) -->
    !,
    parse_pair(M).

parse_members([P|Ms]) -->
    parse_pair(P),
    [','],
    parse_members(Ms).

parse_pair(Key','Value) -->
    object_key(Key),
    [':'],
    parse_value(Value).

object_key(Key) -->
    parse_atom(Key).

parse_value(Value) -->
    parse_array(Value).
parse_value(json(Value)) -->
    !,
    parse_object(json(Value)).

parse_value(Value) -->
    parse_atom(Value).

parse_value(Value) -->
    !,
    parser_number(Value).

parse_atom(Atom) -->
    ['"'],
    {atom_chars(Atom, Chars) },
    parse_string_chars(Chars),
    ['"'].

parse_string_chars([]) --> !, [].
parse_string_chars(Chars) -->
    parse_special_chars(Chars, Chars1),
    !,
    parse_string_chars(Chars1).
parse_string_chars([Char|Chars]) -->
    [Char],
    parse_string_chars(Chars).

parse_special_chars(['\\'|Chars], Chars1) -->
    ['\\'],
    !,
    parse_escape_sequence(Chars, Chars1).
parse_special_chars([Char|Chars], Chars) -->
    { valid_escape_char(Char, EscapedChar) },
    ['\\',EscapedChar].

parse_escape_sequence(Chars, Chars) -->
    ['\\'].

parser_number(Number) -->
    {number_chars(Number, Chars) },
    Chars.

parse_array(json_array([])) -->
    !,
    ['['],
    [']'].
parse_array(json_array(Values)) -->
    ['['],
    parse_array_values(Values),
    [']'].

parse_array_values([Value]) -->
    !,
    parse_value(Value).
parse_array_values([Value|Values]) -->
    parse_value(Value),
    [','],
    parse_array_values(Values).

% Dato un oggetto json e un campo "chiave" ritorna il campo "valore"
json_get(JSON_obj, Fields, Result) :-
        del_quotes(Fields,Field),
        assert_object(JSON_obj),   % Inserisco nel db le coppie Key-Value
	chain_aux(Field, Result),  % Verifico se Field ha associazioni nel db
	retractall(pair((_,_))),   % Svuoto db dalle coppie
        !.
json_get(JSON_obj, [_], _) :-
	retract_object(JSON_obj),
	false.

% verifico se esiste coppia key-value con key noto
chain_aux([Field|Index], Result) :-
	pair((Field, json_array(Array))),
	find_index(Index, Array, Result).
chain_aux(Field, Result) :-
        del_quote(Field,Fields),
	pair((Fields, Result)).
chain_aux([Field|[]], Result) :-
	pair((Field, Result)).

%find_index/3 - recursively find element
%Index in list Array until Result is not an
%array or there are no more indexes.
find_index([Index|MoreIndexes], Array, Result) :-
	nth0(Index, Array, json_array(New_Array)),
	find_index(MoreIndexes, New_Array, Result).

find_index([Index|[]], Array, Result) :-
	nth0(Index, Array, Result).

%inserisco le coppie key-value fra le conoscenze
assert_object(json_obj([Member|MoreMembers])) :-
	assert(pair(Member)),
	assert_object(json_obj(MoreMembers)),
	!.
assert_object(json_obj([])).

%rimuovo le coppie key-value fra le conoscenze
retract_object(json_obj([Member|MoreMembers])) :-
	retract(pair((Member))),
	retract_object(json_obj(MoreMembers)),
	!.
retract_object(json_obj([])).
