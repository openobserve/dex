package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

/* Original SQL table:
create table signup_tokens
(
    email    			text not null  primary key,
    csrf_token	 		text not null,
    validation_token	text not null,
	expiry				integer
);
*/

// Password holds the schema definition for the Password entity.
type SignupToken struct {
	ent.Schema
}

// Fields of the Password.
func (SignupToken) Fields() []ent.Field {
	return []ent.Field{
		field.Text("email").
			SchemaType(textSchema).
			StorageKey("email"). // use email as ID field to make querying easier
			NotEmpty().
			Unique(),
		field.Text("csrf_token").
			SchemaType(textSchema).
			NotEmpty(),
		field.Text("validation_token").
			SchemaType(textSchema).
			NotEmpty(),
		field.Time("expiry").
			SchemaType(timeSchema),
	}
}

// Edges of the Password.
func (SignupToken) Edges() []ent.Edge {
	return []ent.Edge{}
}
