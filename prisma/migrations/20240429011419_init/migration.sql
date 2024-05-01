-- DropIndex
DROP INDEX "User_id_key";

-- AlterTable
ALTER TABLE "User" ALTER COLUMN "role" DROP NOT NULL,
ALTER COLUMN "resettoken" DROP NOT NULL,
ALTER COLUMN "hashedRt" DROP NOT NULL;
