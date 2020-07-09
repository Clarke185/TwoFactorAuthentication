USE [TwoFactorAuthentication]
GO

SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[users](
	[id] [uniqueidentifier] NOT NULL,
	[username] [varchar](50) NOT NULL,
	[hashed_password] [binary](32) NOT NULL,
	[salt] [uniqueidentifier] NOT NULL,
	[email] [varchar](200) NOT NULL,
	[bio] [text] NULL,
	[verified] [bit] NOT NULL,
	[activation_code] [uniqueidentifier] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO

ALTER TABLE [dbo].[users] ADD  DEFAULT (newid()) FOR [id]
GO

ALTER TABLE [dbo].[users] ADD  DEFAULT ((0)) FOR [verified]
GO

ALTER TABLE [dbo].[users]  WITH CHECK ADD  CONSTRAINT [CHK_user_id] CHECK  (([id]<>'00000000-0000-0000-0000-000000000000'))
GO

ALTER TABLE [dbo].[users] CHECK CONSTRAINT [CHK_uid]
GO


