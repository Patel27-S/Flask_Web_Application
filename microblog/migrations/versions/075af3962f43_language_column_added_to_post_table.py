"""language column added to Post table

Revision ID: 075af3962f43
Revises: b7b2f86d4c79
Create Date: 2021-07-17 11:08:39.262235

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '075af3962f43'
down_revision = 'b7b2f86d4c79'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('post', sa.Column('language', sa.String(length=10), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('post', 'language')
    # ### end Alembic commands ###
